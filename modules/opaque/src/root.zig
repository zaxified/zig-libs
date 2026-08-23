// SPDX-License-Identifier: MIT
//! opaque — the OPAQUE augmented password-authenticated key exchange
//! (aPAKE) per RFC 9807, **ristretto255-SHA-512 configuration only**
//! (OPRF: ristretto255-SHA512 per RFC 9497, KDF: HKDF-SHA-512, MAC:
//! HMAC-SHA-512, Hash: SHA-512, KSF: Identity, Group: ristretto255)
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
//!   identities. KSF = Identity (`Stretch(msg) = msg`), the choice the
//!   RFC's own test vectors use; the seam for a real KSF is
//!   `randomizedPassword` below.
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
//!   fake `RegistrationRecord` (random `client_public_key` +
//!   `masking_key`, all-zero envelope) and call `generateKE2` with it;
//!   nothing extra is needed from this module. Not KAT'd here (the
//!   C.2 fake vectors add no new code path).
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

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "OPAQUE — an asymmetric PAKE (RFC 9807), ristretto255-SHA-512 + 3DH — registration and login/AKE. Server compromise reveals no password.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no allocation, no RNG
    .concurrency = .reentrant, // no globals; all state is caller-held values
    .model_after = "RFC 9807 (\"The OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE) Protocol\"), ristretto255-SHA-512 configuration, 3DH AKE, internal-keying Envelope (§4.1), KSF = Identity; OPRF layer = the sibling voprf module (RFC 9497 modeOPRF); std supplies HKDF-SHA-512 / HMAC-SHA-512 / SHA-512 / Ristretto255",
    .deps = .{ "voprf", "ct25519" },
};

// ── configuration constants (RFC 9807 §2 / §7, ristretto255-SHA-512) ─────

/// `Nn` (§2): nonce length (envelope, masking, client/server nonces).
pub const Nn: usize = 32;

/// `Nseed` (§2): seed length (keyshare seeds, the envelope PrivateKey seed).
pub const Nseed: usize = 32;

/// `Nh` (§2.3): Hash output length (SHA-512).
pub const Nh: usize = 64;

/// `Npk` (§7): encoded AKE public key length (ristretto255 element).
pub const Npk: usize = 32;

/// `Nsk` (§7): encoded AKE private key length (ristretto255 scalar).
pub const Nsk: usize = 32;

/// `Nm` (§2.2): MAC output length (HMAC-SHA-512).
pub const Nm: usize = 64;

/// `Nx` (§2.2): KDF Extract output length (HKDF-SHA-512).
pub const Nx: usize = 64;

/// `Nok` (§2.1): OPRF private key length (ristretto255 scalar).
pub const Nok: usize = 32;

/// `Noe` (§2.1): serialized OPRF group element length.
pub const Noe: usize = 32;

/// `Ns` (RFC 9497 §4.1): OPRF blind scalar length. Blinds are produced
/// by the caller's CSPRNG via `scalarFromWideBytes` (re-exported below).
pub const Ns: usize = 32;

/// The `masked_response` length: `Npk + Nn + Nm` (§6.3.1) — the XOR
/// masking of `server_public_key || Envelope`.
pub const masked_response_length: usize = Npk + Nn + Nm;

/// Re-exported from `voprf` (RFC 9497 §4.7.2): reduce 64 uniformly
/// random bytes to a canonical scalar — the intended way for callers
/// with their own CSPRNG to produce the `blind` inputs below.
pub const scalarFromWideBytes = voprf.scalarFromWideBytes;

// ── typed errors (RFC 9807 §9.3) ─────────────────────────────────────────

/// §4.1.3 `EnvelopeRecoveryError`: the envelope auth_tag check failed —
/// on the client this is what a WRONG PASSWORD (or a tampered
/// credential response) looks like.
pub const EnvelopeRecoveryError = error{EnvelopeRecovery};

/// §6.4.3 `ServerAuthenticationError`: KE2's `server_mac` did not
/// verify — the server could not prove knowledge of the record.
pub const ServerAuthenticationError = error{ServerAuthentication};

/// §6.4.4 `ClientAuthenticationError`: KE3's `client_mac` did not
/// verify — the client could not prove knowledge of the password.
pub const ClientAuthenticationError = error{ClientAuthentication};

// ── wire structures (§4.1.1, §5.1, §6.1, §6.3.1) ─────────────────────────

/// §4.1.1 `Envelope`: nonce + auth_tag ONLY (internal keying mode — the
/// client private key is re-derived, never stored or encrypted).
pub const Envelope = struct {
    nonce: [Nn]u8,
    auth_tag: [Nm]u8,

    pub const encoded_length = Nn + Nm; // 96

    pub fn toBytes(e: Envelope) [encoded_length]u8 {
        return e.nonce ++ e.auth_tag;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) Envelope {
        return .{ .nonce = bytes[0..Nn].*, .auth_tag = bytes[Nn..].* };
    }
};

/// §5.1 `RegistrationRequest`: the client's blinded password element.
pub const RegistrationRequest = struct {
    blinded_message: [Noe]u8,

    pub const encoded_length = Noe;

    pub fn toBytes(r: RegistrationRequest) [encoded_length]u8 {
        return r.blinded_message;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) RegistrationRequest {
        return .{ .blinded_message = bytes };
    }
};

/// §5.1 `RegistrationResponse`: the evaluated element + the server's
/// long-term AKE public key.
pub const RegistrationResponse = struct {
    evaluated_message: [Noe]u8,
    server_public_key: [Npk]u8,

    pub const encoded_length = Noe + Npk;

    pub fn toBytes(r: RegistrationResponse) [encoded_length]u8 {
        return r.evaluated_message ++ r.server_public_key;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) RegistrationResponse {
        return .{
            .evaluated_message = bytes[0..Noe].*,
            .server_public_key = bytes[Noe..].*,
        };
    }
};

/// §5.1 `RegistrationRecord` (the RFC's wire name is
/// `registration_upload`): what the server stores per client.
pub const RegistrationRecord = struct {
    client_public_key: [Npk]u8,
    masking_key: [Nh]u8,
    envelope: Envelope,

    pub const encoded_length = Npk + Nh + Envelope.encoded_length; // 192

    pub fn toBytes(r: RegistrationRecord) [encoded_length]u8 {
        return r.client_public_key ++ r.masking_key ++ r.envelope.toBytes();
    }

    pub fn fromBytes(bytes: [encoded_length]u8) RegistrationRecord {
        return .{
            .client_public_key = bytes[0..Npk].*,
            .masking_key = bytes[Npk .. Npk + Nh].*,
            .envelope = Envelope.fromBytes(bytes[Npk + Nh ..].*),
        };
    }
};

/// §6.3.1 `CredentialRequest` (same shape as `RegistrationRequest`).
pub const CredentialRequest = struct {
    blinded_message: [Noe]u8,
};

/// §6.3.1 `CredentialResponse`: evaluated element + masking nonce + the
/// XOR-masked `server_public_key || Envelope`.
pub const CredentialResponse = struct {
    evaluated_message: [Noe]u8,
    masking_nonce: [Nn]u8,
    masked_response: [masked_response_length]u8,

    pub const encoded_length = Noe + Nn + masked_response_length; // 192

    pub fn toBytes(r: CredentialResponse) [encoded_length]u8 {
        return r.evaluated_message ++ r.masking_nonce ++ r.masked_response;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) CredentialResponse {
        return .{
            .evaluated_message = bytes[0..Noe].*,
            .masking_nonce = bytes[Noe .. Noe + Nn].*,
            .masked_response = bytes[Noe + Nn ..].*,
        };
    }
};

/// §6.1 `AuthRequest`: client nonce + client ephemeral public keyshare.
pub const AuthRequest = struct {
    client_nonce: [Nn]u8,
    client_public_keyshare: [Npk]u8,
};

/// §6.1 `KE1` = CredentialRequest || AuthRequest.
pub const KE1 = struct {
    credential_request: CredentialRequest,
    auth_request: AuthRequest,

    pub const encoded_length = Noe + Nn + Npk; // 96

    pub fn toBytes(m: KE1) [encoded_length]u8 {
        return m.credential_request.blinded_message ++
            m.auth_request.client_nonce ++
            m.auth_request.client_public_keyshare;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) KE1 {
        return .{
            .credential_request = .{ .blinded_message = bytes[0..Noe].* },
            .auth_request = .{
                .client_nonce = bytes[Noe .. Noe + Nn].*,
                .client_public_keyshare = bytes[Noe + Nn ..].*,
            },
        };
    }
};

/// §6.1 `AuthResponse`: server nonce + server ephemeral public
/// keyshare + the server's transcript MAC.
pub const AuthResponse = struct {
    server_nonce: [Nn]u8,
    server_public_keyshare: [Npk]u8,
    server_mac: [Nm]u8,
};

/// §6.1 `KE2` = CredentialResponse || AuthResponse.
pub const KE2 = struct {
    credential_response: CredentialResponse,
    auth_response: AuthResponse,

    pub const encoded_length = CredentialResponse.encoded_length + Nn + Npk + Nm; // 320

    pub fn toBytes(m: KE2) [encoded_length]u8 {
        return m.credential_response.toBytes() ++
            m.auth_response.server_nonce ++
            m.auth_response.server_public_keyshare ++
            m.auth_response.server_mac;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) KE2 {
        const cr = CredentialResponse.encoded_length;
        return .{
            .credential_response = CredentialResponse.fromBytes(bytes[0..cr].*),
            .auth_response = .{
                .server_nonce = bytes[cr .. cr + Nn].*,
                .server_public_keyshare = bytes[cr + Nn .. cr + Nn + Npk].*,
                .server_mac = bytes[cr + Nn + Npk ..].*,
            },
        };
    }
};

/// §6.1 `KE3`: the client's transcript MAC.
pub const KE3 = struct {
    client_mac: [Nm]u8,

    pub const encoded_length = Nm;

    pub fn toBytes(m: KE3) [encoded_length]u8 {
        return m.client_mac;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) KE3 {
        return .{ .client_mac = bytes };
    }
};

/// §4 optional application identities. When a field is `null` it
/// defaults to the corresponding public key (§4
/// `CreateCleartextCredentials`) — both sides must agree on the same
/// choice, and it must match what registration used.
pub const Identities = struct {
    client: ?[]const u8 = null,
    server: ?[]const u8 = null,
};

/// An AKE key pair as produced by §6.4.1.1
/// `DeriveDiffieHellmanKeyPair` (see `deriveAkeKeyPair`).
pub const AkeKeyPair = struct {
    private_key: [Nsk]u8,
    public_key: [Npk]u8,
};

// ── KDF helpers ──────────────────────────────────────────────────────────

/// RFC 5869 HKDF-Expand (HMAC-SHA-512) with a multi-part `info` and
/// `L <= 2 * Nx` — every `Expand` RFC 9807 performs composes `info` by
/// concatenation, and the longest output is the `Npk + Nn + Nm = 128`
/// byte `credential_response_pad`, so two HMAC blocks suffice:
/// `T(1) = HMAC(prk, info || 0x01)`, `T(2) = HMAC(prk, T(1) || info ||
/// 0x02)`. Pinned against `std.crypto.kdf.hkdf.HkdfSha512.expand` by
/// the `"expandMulti agrees with std"` test below (and transitively by
/// every KAT).
fn expandMulti(out: []u8, prk: *const [Nx]u8, info_parts: []const []const u8) void {
    std.debug.assert(out.len >= 1 and out.len <= 2 * Nx);
    var t: [Nx]u8 = undefined;
    var mac = HmacSha512.init(prk);
    for (info_parts) |part| mac.update(part);
    mac.update(&[1]u8{0x01});
    mac.final(&t);
    const head = @min(out.len, Nx);
    @memcpy(out[0..head], t[0..head]);
    if (out.len > Nx) {
        var mac2 = HmacSha512.init(prk);
        mac2.update(&t);
        for (info_parts) |part| mac2.update(part);
        mac2.update(&[1]u8{0x02});
        mac2.final(&t);
        @memcpy(out[Nx..], t[0 .. out.len - Nx]);
    }
    std.crypto.secureZero(u8, &t);
}

/// `I2OSP(len, 2)` (§1.2) — the 2-byte big-endian length prefix used
/// throughout the envelope MAC and the AKE preamble.
fn i2osp2(len: usize) [2]u8 {
    std.debug.assert(len <= 0xffff);
    var out: [2]u8 = undefined;
    std.mem.writeInt(u16, &out, @intCast(len), .big);
    return out;
}

// ── key derivation (§4.1.1, §6.4.1.1) ────────────────────────────────────

/// §6.4.1.1 `DeriveDiffieHellmanKeyPair(seed)` = RFC 9497 §3.2.1
/// `DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")` in the
/// base-OPRF-mode context — via `voprf.deriveKeyPair`. Public because
/// servers use it to create their long-term AKE key pair at setup.
pub fn deriveAkeKeyPair(seed: [Nseed]u8) error{DeriveKeyPairFailed}!AkeKeyPair {
    const kp = try voprf.deriveKeyPair(.oprf, seed, "OPAQUE-DeriveDiffieHellmanKeyPair");
    return .{ .private_key = kp.sk, .public_key = kp.pk.toBytes() };
}

/// §5.2.2/§6.3.2.2's per-client OPRF key: `seed = Expand(oprf_seed,
/// credential_identifier || "OprfKey", Nok)`, then RFC 9497
/// `DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")` via `voprf`.
fn deriveOprfKey(oprf_seed: [Nh]u8, credential_identifier: []const u8) error{DeriveKeyPairFailed}![Nok]u8 {
    var seed: [Nok]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    expandMulti(&seed, &oprf_seed, &.{ credential_identifier, "OprfKey" });
    const kp = try voprf.deriveKeyPair(.oprf, seed, "OPAQUE-DeriveKeyPair");
    return kp.sk;
}

/// §6.4.1.1 `DiffieHellman(k, B)`: RFC 9496 Decode (with §10.7 input
/// validation: canonical + non-identity, via `voprf.Element.fromBytes`)
/// then a scalar multiplication that is constant-time in `k` AND does not
/// branch on its own result — `ct25519.mulRistretto`, not
/// `Ristretto255.mul`. Output is the 32-byte encoded element.
///
/// **How §6.4.1.1's "the shared secret MUST NOT be the identity element"
/// is satisfied.** It used to be satisfied by `catch`ing the rejection
/// std's `mul` performs on its own output — i.e. by branching on a value
/// derived from the SECRET `private_key`. It is now satisfied
/// structurally, which is stronger: ristretto255 is a group of PRIME
/// order `L` (that is the entire point of the ristretto abstraction — no
/// cofactor, no small subgroup), and `fromBytes` has already rejected the
/// identity, so `B` generates the whole group and `k*B` is the identity
/// **iff `k == 0 (mod L)`**. A peer therefore cannot induce it at all,
/// with any element it can encode. `k` is either a `voprf.deriveKeyPair`
/// output (the RFC 9497 §3.2.1 loop rejects zero) or a caller-supplied
/// long-term server key held to the same rule. There is nothing left for
/// a runtime check to catch that a branch on `k` would not simply leak.
fn diffieHellman(private_key: [Nsk]u8, public_key: [Npk]u8) error{InvalidPublicKey}![Npk]u8 {
    const point = voprf.Element.fromBytes(public_key) catch return error.InvalidPublicKey;
    return ct25519.mulRistretto(point.p, private_key).toBytes();
}

/// §5.2.3/§6.3.2.3's `randomized_password` = `Extract("",
/// oprf_output || Stretch(oprf_output))` with KSF = Identity
/// (`Stretch(msg) = msg`, the RFC test-vector configuration — a
/// production deployment wanting Argon2id would replace the second
/// `update` here and nothing else).
fn randomizedPassword(
    password: []const u8,
    blind: [Ns]u8,
    evaluated_message: [Noe]u8,
) error{ InvalidMessage, InvalidBlind }![Nx]u8 {
    const evaluated = voprf.Element.fromBytes(evaluated_message) catch return error.InvalidMessage;
    var oprf_output = try voprf.finalize(password, blind, evaluated);
    defer std.crypto.secureZero(u8, &oprf_output);
    var extract = HkdfSha512.extractInit("");
    extract.update(&oprf_output);
    extract.update(&oprf_output); // stretched_oprf_output (Identity KSF)
    var prk: [Nx]u8 = undefined;
    extract.final(&prk);
    return prk;
}

// ── envelope (§4.1) ──────────────────────────────────────────────────────

/// The §4.1.2/§4.1.3 auth_tag: `MAC(auth_key, envelope_nonce ||
/// CleartextCredentials)` where the §4 `CleartextCredentials`
/// serialization is `server_public_key || I2OSP(len(server_identity),
/// 2) || server_identity || I2OSP(len(client_identity), 2) ||
/// client_identity` (identities already defaulted by the caller).
fn envelopeAuthTag(
    auth_key: *const [Nh]u8,
    envelope_nonce: [Nn]u8,
    server_public_key: [Npk]u8,
    server_identity: []const u8,
    client_identity: []const u8,
) [Nm]u8 {
    var mac = HmacSha512.init(auth_key);
    mac.update(&envelope_nonce);
    mac.update(&server_public_key);
    mac.update(&i2osp2(server_identity.len));
    mac.update(server_identity);
    mac.update(&i2osp2(client_identity.len));
    mac.update(client_identity);
    var tag: [Nm]u8 = undefined;
    mac.final(&tag);
    return tag;
}

const StoreResult = struct {
    envelope: Envelope,
    client_public_key: [Npk]u8,
    masking_key: [Nh]u8,
    export_key: [Nh]u8,
};

/// §4.1.2 `Store`: derive `masking_key`/`auth_key`/`export_key`/the
/// private-key seed from `randomized_password`, derive the client AKE
/// key pair (internal keying), and MAC the cleartext credentials. On
/// the (negligible) `DeriveKeyPairFailed`, re-run registration with a
/// fresh `envelope_nonce` per §4.1.2.
fn store(
    randomized_password: *const [Nx]u8,
    server_public_key: [Npk]u8,
    identities: Identities,
    envelope_nonce: [Nn]u8,
) error{DeriveKeyPairFailed}!StoreResult {
    var masking_key: [Nh]u8 = undefined;
    expandMulti(&masking_key, randomized_password, &.{"MaskingKey"});
    var auth_key: [Nh]u8 = undefined;
    defer std.crypto.secureZero(u8, &auth_key);
    expandMulti(&auth_key, randomized_password, &.{ &envelope_nonce, "AuthKey" });
    var export_key: [Nh]u8 = undefined;
    expandMulti(&export_key, randomized_password, &.{ &envelope_nonce, "ExportKey" });
    var seed: [Nseed]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    expandMulti(&seed, randomized_password, &.{ &envelope_nonce, "PrivateKey" });
    const kp = try deriveAkeKeyPair(seed);

    const server_identity = identities.server orelse &server_public_key;
    const client_identity = identities.client orelse &kp.public_key;
    const tag = envelopeAuthTag(&auth_key, envelope_nonce, server_public_key, server_identity, client_identity);

    return .{
        .envelope = .{ .nonce = envelope_nonce, .auth_tag = tag },
        .client_public_key = kp.public_key,
        .masking_key = masking_key,
        .export_key = export_key,
    };
}

const RecoverResult = struct {
    client_private_key: [Nsk]u8,
    client_public_key: [Npk]u8,
    export_key: [Nh]u8,
};

/// §4.1.3 `Recover`: re-derive the keys from `randomized_password` and
/// the envelope nonce, re-derive the client key pair, recompute the
/// auth_tag over the cleartext credentials, and compare timing-safe.
/// Fails CLOSED (`error.EnvelopeRecovery`) on any mismatch — including
/// the negligible key-derivation failure — releasing nothing.
fn recover(
    randomized_password: *const [Nx]u8,
    server_public_key: [Npk]u8,
    envelope: Envelope,
    identities: Identities,
) EnvelopeRecoveryError!RecoverResult {
    var auth_key: [Nh]u8 = undefined;
    defer std.crypto.secureZero(u8, &auth_key);
    expandMulti(&auth_key, randomized_password, &.{ &envelope.nonce, "AuthKey" });
    var export_key: [Nh]u8 = undefined;
    expandMulti(&export_key, randomized_password, &.{ &envelope.nonce, "ExportKey" });
    var seed: [Nseed]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    expandMulti(&seed, randomized_password, &.{ &envelope.nonce, "PrivateKey" });
    const kp = deriveAkeKeyPair(seed) catch return error.EnvelopeRecovery;

    const server_identity = identities.server orelse &server_public_key;
    const client_identity = identities.client orelse &kp.public_key;
    const expected_tag = envelopeAuthTag(&auth_key, envelope.nonce, server_public_key, server_identity, client_identity);
    if (!timing_safe.eql([Nm]u8, envelope.auth_tag, expected_tag))
        return error.EnvelopeRecovery;

    return .{
        .client_private_key = kp.private_key,
        .client_public_key = kp.public_key,
        .export_key = export_key,
    };
}

// ── registration (§5.2) ──────────────────────────────────────────────────

/// §5.2.1 `CreateRegistrationRequest(password)` with a caller-supplied
/// `blind` (the RFC's `Blind` samples it internally; here it MUST be a
/// fresh uniformly random scalar from the caller's CSPRNG — see
/// `scalarFromWideBytes`). The caller keeps `blind` secret for
/// `finalizeRegistrationRequest`.
pub fn createRegistrationRequest(
    password: []const u8,
    blind: [Ns]u8,
) voprf.BlindError!RegistrationRequest {
    const blinded = try voprf.blind(.oprf, password, blind);
    return .{ .blinded_message = blinded.toBytes() };
}

pub const CreateRegistrationResponseError = error{ InvalidMessage, DeriveKeyPairFailed, InvalidSecretKey };

/// §5.2.2 `CreateRegistrationResponse`: derive the per-client OPRF key
/// from `oprf_seed` + `credential_identifier` and evaluate the blinded
/// element (both via `voprf`). On the negligible `DeriveKeyPairFailed`,
/// choose a new `credential_identifier` per §5.2.2.
pub fn createRegistrationResponse(
    request: RegistrationRequest,
    server_public_key: [Npk]u8,
    credential_identifier: []const u8,
    oprf_seed: [Nh]u8,
) CreateRegistrationResponseError!RegistrationResponse {
    const oprf_key = try deriveOprfKey(oprf_seed, credential_identifier);
    const blinded = voprf.Element.fromBytes(request.blinded_message) catch return error.InvalidMessage;
    const evaluated = voprf.blindEvaluate(oprf_key, blinded);
    return .{
        .evaluated_message = evaluated.toBytes(),
        .server_public_key = server_public_key,
    };
}

pub const FinalizeRegistrationError = error{ InvalidMessage, InvalidBlind, DeriveKeyPairFailed };

pub const FinalizeRegistrationResult = struct {
    /// The `RegistrationRecord` to send to the server (§5.1
    /// `registration_upload`).
    record: RegistrationRecord,
    /// The client-only export key (§10.4) — same value re-derived at
    /// every successful login.
    export_key: [Nh]u8,
};

/// §5.2.3 `FinalizeRegistrationRequest`: unblind + finalize the OPRF
/// (via `voprf.finalize`), stretch (Identity KSF) and extract
/// `randomized_password`, then §4.1.2 `Store` with the caller-supplied
/// `envelope_nonce` (the RFC samples it inside `Store`; fresh random
/// per registration). `identities` must match what logins will use.
pub fn finalizeRegistrationRequest(
    password: []const u8,
    blind: [Ns]u8,
    response: RegistrationResponse,
    identities: Identities,
    envelope_nonce: [Nn]u8,
) FinalizeRegistrationError!FinalizeRegistrationResult {
    var rp = try randomizedPassword(password, blind, response.evaluated_message);
    defer std.crypto.secureZero(u8, &rp);
    const stored = try store(&rp, response.server_public_key, identities, envelope_nonce);
    return .{
        .record = .{
            .client_public_key = stored.client_public_key,
            .masking_key = stored.masking_key,
            .envelope = stored.envelope,
        },
        .export_key = stored.export_key,
    };
}

// ── online AKE (§6) ──────────────────────────────────────────────────────

/// §6's `ClientState`: everything the client must hold between
/// `generateKE1` and `generateKE3`. `password` is borrowed (the caller
/// keeps it alive and secret); the rest are secrets to erase after the
/// login completes (§6: "ephemeral and should be erased").
pub const ClientLoginState = struct {
    password: []const u8,
    blind: [Ns]u8,
    /// The client's ephemeral AKE private keyshare (`client_secret`).
    client_secret: [Nsk]u8,
    ke1: KE1,
};

/// §6.4's `ServerAkeState`: held between `generateKE2` and
/// `serverFinish`; ephemeral, erase after the login completes.
pub const ServerLoginState = struct {
    expected_client_mac: [Nm]u8,
    session_key: [Nx]u8,
};

pub const GenerateKE1Error = error{ InvalidInput, InvalidBlind, DeriveKeyPairFailed };

pub const GenerateKE1Result = struct {
    ke1: KE1,
    state: ClientLoginState,
};

/// §6.2.1 `GenerateKE1` (= `CreateCredentialRequest` +
/// `AuthClientStart`) with caller-supplied randomness: `blind` (fresh
/// random scalar), `client_nonce` (fresh Nn bytes), and
/// `client_keyshare_seed` (fresh Nseed bytes; the ephemeral keyshare
/// is derived from it per §6.4.1.1).
pub fn generateKE1(
    password: []const u8,
    blind: [Ns]u8,
    client_nonce: [Nn]u8,
    client_keyshare_seed: [Nseed]u8,
) GenerateKE1Error!GenerateKE1Result {
    const blinded = try voprf.blind(.oprf, password, blind);
    const keyshare = try deriveAkeKeyPair(client_keyshare_seed);
    const ke1 = KE1{
        .credential_request = .{ .blinded_message = blinded.toBytes() },
        .auth_request = .{
            .client_nonce = client_nonce,
            .client_public_keyshare = keyshare.public_key,
        },
    };
    return .{ .ke1 = ke1, .state = .{
        .password = password,
        .blind = blind,
        .client_secret = keyshare.private_key,
        .ke1 = ke1,
    } };
}

pub const GenerateKE2Error = error{ InvalidMessage, InvalidPublicKey, DeriveKeyPairFailed, InvalidSecretKey };

pub const GenerateKE2Result = struct {
    ke2: KE2,
    state: ServerLoginState,
};

/// §6.2.2 `GenerateKE2` (= `CreateCredentialResponse` +
/// `AuthServerRespond`) with caller-supplied randomness
/// (`masking_nonce`, `server_nonce`, `server_keyshare_seed` — all
/// fresh random per login). `context` is the application-configured
/// shared context string (§7; both sides must agree; may be empty).
/// For an UNREGISTERED user, pass the server's one persistent fake
/// record (§6.3.2.2) — see the module doc comment.
pub fn generateKE2(
    server_private_key: [Nsk]u8,
    server_public_key: [Npk]u8,
    record: RegistrationRecord,
    credential_identifier: []const u8,
    oprf_seed: [Nh]u8,
    ke1: KE1,
    identities: Identities,
    context: []const u8,
    masking_nonce: [Nn]u8,
    server_nonce: [Nn]u8,
    server_keyshare_seed: [Nseed]u8,
) GenerateKE2Error!GenerateKE2Result {
    // §6.3.2.2 CreateCredentialResponse.
    const oprf_key = try deriveOprfKey(oprf_seed, credential_identifier);
    const blinded = voprf.Element.fromBytes(ke1.credential_request.blinded_message) catch
        return error.InvalidMessage;
    const evaluated = voprf.blindEvaluate(oprf_key, blinded);

    var masked = credentialResponsePad(&record.masking_key, masking_nonce);
    const plaintext = server_public_key ++ record.envelope.toBytes();
    for (&masked, plaintext) |*b, p| b.* ^= p;

    const credential_response = CredentialResponse{
        .evaluated_message = evaluated.toBytes(),
        .masking_nonce = masking_nonce,
        .masked_response = masked,
    };

    // §6.4.4 AuthServerRespond.
    const keyshare = try deriveAkeKeyPair(server_keyshare_seed);
    const dh1 = try diffieHellman(keyshare.private_key, ke1.auth_request.client_public_keyshare);
    const dh2 = try diffieHellman(server_private_key, ke1.auth_request.client_public_keyshare);
    const dh3 = try diffieHellman(keyshare.private_key, record.client_public_key);
    var ikm = dh1 ++ dh2 ++ dh3;
    defer std.crypto.secureZero(u8, &ikm);

    const server_identity = identities.server orelse &server_public_key;
    const client_identity = identities.client orelse &record.client_public_key;
    const schedule = runKeySchedule(
        &ikm,
        context,
        client_identity,
        server_identity,
        ke1,
        credential_response,
        server_nonce,
        keyshare.public_key,
    );

    return .{
        .ke2 = .{
            .credential_response = credential_response,
            .auth_response = .{
                .server_nonce = server_nonce,
                .server_public_keyshare = keyshare.public_key,
                .server_mac = schedule.server_mac,
            },
        },
        .state = .{
            .expected_client_mac = schedule.client_mac,
            .session_key = schedule.session_key,
        },
    };
}

pub const GenerateKE3Error = error{
    InvalidMessage,
    InvalidBlind,
    InvalidPublicKey,
    EnvelopeRecovery,
    ServerAuthentication,
};

pub const GenerateKE3Result = struct {
    ke3: KE3,
    /// The shared session secret — MUST NOT be used unless this call
    /// succeeded (server authentication verified).
    session_key: [Nx]u8,
    /// The client-only export key (§10.4), identical to the one from
    /// registration. Only released after the server_mac verified.
    export_key: [Nh]u8,
};

/// §6.2.3 `GenerateKE3` (= `RecoverCredentials` +
/// `AuthClientFinalize`): unmask the credential response, recover the
/// envelope (wrong password ⇒ `error.EnvelopeRecovery`, fail closed),
/// run the client side of 3DH, verify the server's transcript MAC
/// timing-safe (mismatch ⇒ `error.ServerAuthentication`, fail closed),
/// and only then produce KE3 + `session_key` + `export_key`.
/// `identities` and `context` must match the server's.
pub fn generateKE3(
    state: ClientLoginState,
    identities: Identities,
    context: []const u8,
    ke2: KE2,
) GenerateKE3Error!GenerateKE3Result {
    // §6.3.2.3 RecoverCredentials.
    var rp = try randomizedPassword(state.password, state.blind, ke2.credential_response.evaluated_message);
    defer std.crypto.secureZero(u8, &rp);
    var masking_key: [Nh]u8 = undefined;
    defer std.crypto.secureZero(u8, &masking_key);
    expandMulti(&masking_key, &rp, &.{"MaskingKey"});

    var plaintext = credentialResponsePad(&masking_key, ke2.credential_response.masking_nonce);
    for (&plaintext, ke2.credential_response.masked_response) |*b, m| b.* ^= m;
    const server_public_key: [Npk]u8 = plaintext[0..Npk].*;
    const envelope = Envelope.fromBytes(plaintext[Npk..].*);

    const credentials = try recover(&rp, server_public_key, envelope, identities);

    // §6.4.3 AuthClientFinalize.
    const dh1 = try diffieHellman(state.client_secret, ke2.auth_response.server_public_keyshare);
    const dh2 = try diffieHellman(state.client_secret, server_public_key);
    const dh3 = try diffieHellman(credentials.client_private_key, ke2.auth_response.server_public_keyshare);
    var ikm = dh1 ++ dh2 ++ dh3;
    defer std.crypto.secureZero(u8, &ikm);

    const server_identity = identities.server orelse &server_public_key;
    const client_identity = identities.client orelse &credentials.client_public_key;
    const schedule = runKeySchedule(
        &ikm,
        context,
        client_identity,
        server_identity,
        state.ke1,
        ke2.credential_response,
        ke2.auth_response.server_nonce,
        ke2.auth_response.server_public_keyshare,
    );

    if (!timing_safe.eql([Nm]u8, ke2.auth_response.server_mac, schedule.server_mac))
        return error.ServerAuthentication;

    return .{
        .ke3 = .{ .client_mac = schedule.client_mac },
        .session_key = schedule.session_key,
        .export_key = credentials.export_key,
    };
}

/// §6.2.4 `ServerFinish` (= `AuthServerFinalize`): verify the client's
/// transcript MAC timing-safe and release `session_key` if and only if
/// it matches (`error.ClientAuthentication` otherwise, fail closed —
/// this check is what gives full forward secrecy against active
/// attackers, §6.2.4).
pub fn serverFinish(state: ServerLoginState, ke3: KE3) ClientAuthenticationError![Nx]u8 {
    if (!timing_safe.eql([Nm]u8, ke3.client_mac, state.expected_client_mac))
        return error.ClientAuthentication;
    return state.session_key;
}

// ── credential masking (§6.3.2.2/§6.3.2.3) ───────────────────────────────

/// `credential_response_pad = Expand(masking_key, masking_nonce ||
/// "CredentialResponsePad", Npk + Nn + Nm)` — the XOR pad over
/// `server_public_key || Envelope` in both directions.
fn credentialResponsePad(masking_key: *const [Nh]u8, masking_nonce: [Nn]u8) [masked_response_length]u8 {
    var pad: [masked_response_length]u8 = undefined;
    expandMulti(&pad, masking_key, &.{ &masking_nonce, "CredentialResponsePad" });
    return pad;
}

// ── 3DH key schedule (§6.4.2) ────────────────────────────────────────────

/// §6.4.2.1 `Derive-Secret(Secret, Label, Transcript-Hash)` =
/// `Expand(Secret, CustomLabel, Nx)` with the TLS 1.3-style
/// `CustomLabel = I2OSP(Nx, 2) || I2OSP(len("OPAQUE-" || Label), 1) ||
/// "OPAQUE-" || Label || I2OSP(len(Context), 1) || Context`.
fn deriveSecret(secret: *const [Nx]u8, comptime label: []const u8, transcript: []const u8) [Nx]u8 {
    const full_label = "OPAQUE-" ++ label;
    comptime std.debug.assert(full_label.len >= 8 and full_label.len <= 255);
    std.debug.assert(transcript.len <= 255);
    var out: [Nx]u8 = undefined;
    expandMulti(&out, secret, &.{
        &[2]u8{ 0, Nx },
        &[1]u8{full_label.len},
        full_label,
        &[1]u8{@intCast(transcript.len)},
        transcript,
    });
    return out;
}

const KeySchedule = struct {
    server_mac: [Nm]u8,
    client_mac: [Nm]u8,
    session_key: [Nx]u8,
};

/// The shared §6.4.2 core both sides run identically: stream the
/// §6.4.2.1 `Preamble` into SHA-512 (`"OPAQUEv1-" || I2OSP(len(
/// context), 2) || context || I2OSP(len(client_identity), 2) ||
/// client_identity || KE1 || I2OSP(len(server_identity), 2) ||
/// server_identity || credential_response || server_nonce ||
/// server_public_keyshare`), then §6.4.2.2 `DeriveKeys(ikm,
/// preamble)`: `prk = Extract("", ikm)`, `handshake_secret` /
/// `session_key` via `Derive-Secret(..., Hash(preamble))`, `Km2`/`Km3`
/// from `handshake_secret`, `server_mac = MAC(Km2, Hash(preamble))`,
/// and `client_mac = MAC(Km3, Hash(preamble || server_mac))`.
fn runKeySchedule(
    ikm: *const [3 * Npk]u8,
    context: []const u8,
    client_identity: []const u8,
    server_identity: []const u8,
    ke1: KE1,
    credential_response: CredentialResponse,
    server_nonce: [Nn]u8,
    server_public_keyshare: [Npk]u8,
) KeySchedule {
    var transcript = Sha512.init(.{});
    transcript.update("OPAQUEv1-");
    transcript.update(&i2osp2(context.len));
    transcript.update(context);
    transcript.update(&i2osp2(client_identity.len));
    transcript.update(client_identity);
    transcript.update(&ke1.toBytes());
    transcript.update(&i2osp2(server_identity.len));
    transcript.update(server_identity);
    transcript.update(&credential_response.toBytes());
    transcript.update(&server_nonce);
    transcript.update(&server_public_keyshare);

    var preamble_hash: [Nh]u8 = undefined;
    var preamble_only = transcript; // value copy: Hash(preamble)
    preamble_only.final(&preamble_hash);

    var prk = HkdfSha512.extract("", ikm);
    defer std.crypto.secureZero(u8, &prk);
    var handshake_secret = deriveSecret(&prk, "HandshakeSecret", &preamble_hash);
    defer std.crypto.secureZero(u8, &handshake_secret);
    const session_key = deriveSecret(&prk, "SessionKey", &preamble_hash);
    var km2 = deriveSecret(&handshake_secret, "ServerMAC", "");
    defer std.crypto.secureZero(u8, &km2);
    var km3 = deriveSecret(&handshake_secret, "ClientMAC", "");
    defer std.crypto.secureZero(u8, &km3);

    var server_mac: [Nm]u8 = undefined;
    HmacSha512.create(&server_mac, &preamble_hash, &km2);

    // client_mac covers Hash(preamble || server_mac).
    transcript.update(&server_mac);
    var full_transcript_hash: [Nh]u8 = undefined;
    transcript.final(&full_transcript_hash);
    var client_mac: [Nm]u8 = undefined;
    HmacSha512.create(&client_mac, &full_transcript_hash, &km3);

    return .{
        .server_mac = server_mac,
        .client_mac = client_mac,
        .session_key = session_key,
    };
}

// ── tests ────────────────────────────────────────────────────────────────

test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
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
test "diffieHellman REPORTS NOTHING about a degenerate private key (ct25519)" {
    // A perfectly valid, non-identity peer element.
    const peer = voprf.Element.generator.toBytes();
    const shared = try diffieHellman([_]u8{0} ** Nsk, peer);
    // k = 0 => the identity, which ristretto255 encodes as 32 zero bytes.
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** Npk, &shared);

    // std really does refuse this — pinning that the line above is a
    // behaviour change and not a tautology.
    const point = try voprf.Element.fromBytes(peer);
    try std.testing.expectError(error.IdentityElement, point.p.mul([_]u8{0} ** Nsk));

    // And a nonzero key still agrees with std byte-for-byte, so the swap
    // changed the leak and nothing else.
    const k = voprf.scalarFromWideBytes([_]u8{0x3c} ** 64);
    const want = try point.p.mul(k);
    try std.testing.expectEqualSlices(u8, &want.toBytes(), &(try diffieHellman(k, peer)));
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
