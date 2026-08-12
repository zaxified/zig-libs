// SPDX-License-Identifier: MIT
//! X3DH (Extended Triple Diffie-Hellman, signal.org/docs/specifications/x3dh)
//! — the Signal Protocol's asynchronous initial key-agreement: Alice
//! fetches a "prekey bundle" Bob published to a server while offline, and
//! from it alone derives a shared secret `SK` (plus associated data `AD`)
//! that gives mutual authentication and forward secrecy of the FIRST
//! message, without either party needing to be online at the same time.
//!
//! **Status: COMPLETE.** The four-DH + HKDF composition
//! (`initiateUnverified`, `respond`), every wire codec (`PreKeyBundle`,
//! `InitialMessage`), and the XEdDSA-backed entry points (`initiate`,
//! `generateSignedPreKey` — see the sibling `xeddsa.zig`, now
//! implemented) are all real and tested. `initiateUnverified` remains so
//! the DH/HKDF agreement stays testable in isolation from signature
//! verification — but `initiate` is the entry point a real caller should
//! use (see the threat model in `SPEC.md`).
//!
//! Four Diffie-Hellman computations (spec § "X3DH key agreement", step 3):
//!
//! ```text
//! DH1 = DH(IKA,  SPKB)      DH2 = DH(EKA, IKB)
//! DH3 = DH(EKA,  SPKB)      DH4 = DH(EKA, OPKB)   [only if Bob published an OPK]
//! SK  = KDF(F || DH1 || DH2 || DH3 || DH4)
//! ```
//!
//! `IK*` = long-term identity key, `SPKB` = Bob's signed prekey, `EKA` =
//! Alice's fresh ephemeral key, `OPKB` = one of Bob's one-time prekeys
//! (optional — Bob's bundle may have run out; DH4/its term is then simply
//! omitted, per spec). All four are `std.crypto.dh.X25519` keys; DH itself
//! is `X25519.scalarmult`, symmetric in the usual Diffie-Hellman sense
//! (`DH(a_priv, b_pub) == DH(b_priv, a_pub)`), which is exactly what lets
//! `initiateUnverified` (Alice's side) and `respond` (Bob's side) land on
//! the identical `SK` from their own, disjoint private-key material.
//!
//! `F` is the spec's fixed domain-separation prefix: for a Montgomery
//! curve whose field elements can collide with low-order points (X25519's
//! documented "contributory behavior" caveat), the spec prepends a
//! constant so an all-identity DH output can never accidentally look like
//! a valid `KM` prefix from a different key size/curve. For X25519, `F` is
//! 32 bytes of `0xFF` (`f_constant` below).
//!
//! `KDF(KM)` = HKDF (spec § "KDF"): `HKDF-Extract(salt = zeroes(hash_len),
//! IKM = KM)` then `HKDF-Expand(PRK, info, hash_len)`. This module uses
//! HKDF-SHA256 (32-byte output, matching X25519's 32-byte field — the same
//! curve/hash pairing this repo's `noise.DefaultSuite`/`spake2plus` use for
//! their own 25519-scale constructions); the spec also permits SHA-512 for
//! larger curves (X448) — out of scope here. `info` is an
//! application-specific constant the spec leaves undefined; this module
//! picks its own (`x3dh_info` below), like `bolt8`/`noise` pick their own
//! protocol-name strings for an analogous Noise `info` parameter.
//!
//! Associated data `AD = Encode(IKA) || Encode(IKB)` (spec § "Sending the
//! initial message") — for X25519, `Encode()` is simply the raw 32-byte
//! public key, so `AD` is the 64-byte concatenation of both parties'
//! identity public keys. A higher-level protocol MAY append more data (the
//! spec explicitly allows this); this module returns exactly the spec's
//! own 64-byte core so a caller can extend it.
//!
//! **Part 2 boundary (Double Ratchet, not implemented in THIS FILE):** X3DH's
//! output IS `SK`/`AD` — nothing more. The spec explicitly hands off to
//! "a post-X3DH protocol" for actually encrypting messages; Signal's own
//! choice — and this arc's Part 2, implemented and COMPLETE in the sibling
//! `ratchet.zig` — is the Double Ratchet, seeded with `SK` as its initial
//! root key. `InitialMessage.ciphertext` here is therefore an OPAQUE,
//! caller-supplied byte slice — this module carries it, but does not
//! produce or interpret it (no AEAD is invoked by this file at all). See
//! `../README.md`'s "Part 2" section and `ratchet.zig`'s own module doc
//! comment.

const std = @import("std");
const xeddsa = @import("xeddsa.zig");
const entropy = @import("entropy");
const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const key_length: usize = X25519.public_length; // 32
pub const shared_secret_length: usize = 32;
pub const associated_data_length: usize = key_length * 2; // 64
pub const signature_length: usize = 64; // xeddsa.Signature

/// Spec § "KDF": the fixed 32-byte `0xFF` domain-separation prefix for
/// X25519 (a 57-byte `0xFF` prefix is specified for X448 — not implemented
/// here).
pub const f_constant = [_]u8{0xFF} ** 32;

/// This module's own `info` constant for the final HKDF-Expand step
/// (spec § "KDF": "An application-specific byte sequence" — the spec
/// deliberately leaves this undefined; this is zig-libs' choice, not a
/// value from the spec text itself).
pub const x3dh_info = "zig-libs/signal/x3dh/v1";

// ── key types (spec § "X3DH parties") ───────────────────────────────────
//
// Every key in X3DH is a plain X25519 keypair; the spec distinguishes
// them only by ROLE (identity / signed-prekey / one-time-prekey /
// ephemeral), not by wire shape. These aliases exist so call sites read
// like the spec's own vocabulary rather than a bag of `X25519.KeyPair`s.

/// `IKA`/`IKB` — a party's long-term identity keypair. Also the signing
/// key XEdDSA (`xeddsa.zig`) uses to sign a `SignedPreKey` — spec: "Bob's
/// identity key IK_B ... is also used ... to sign SPK_B".
pub const IdentityKey = X25519.KeyPair;

/// `EKA` — Alice's single-use ephemeral keypair, freshly generated per
/// X3DH run (`initiateUnverified` draws one via `io`).
pub const EphemeralKey = X25519.KeyPair;

/// `SPKB` — Bob's medium-term signed prekey: an X25519 keypair plus the
/// XEdDSA signature (`sig.zig`) Bob's identity key produced over the
/// PUBLIC half, and the numeric id Bob's bundle publishes it under (so
/// Alice's `InitialMessage` can tell a later Bob which SPK she used, after
/// Bob has rotated to a newer one).
pub const SignedPreKey = struct {
    key_pair: X25519.KeyPair,
    signature: xeddsa.Signature,
    id: u32,
};

/// `OPKB` — one of Bob's one-time prekeys: a plain X25519 keypair plus its
/// id. Consumed (deleted server-side) after one use — spec: "Bob can also
/// upload a queue of one-time prekeys... A one-time prekey is deleted when
/// used, or after some interval". Not signed directly (only `SPKB` is
/// signed) — Bob's `IKB` signature over `SPKB` is what anchors trust for
/// the WHOLE bundle, per spec.
pub const OneTimePreKey = struct {
    key_pair: X25519.KeyPair,
    id: u32,
};

/// A fresh X25519 keypair for ANY of the four roles above — the one place
/// this module and `ratchet.zig` mint private keys.
///
/// Body-identical to `std.crypto.dh.X25519.KeyPair.generate`, with one
/// substitution: the seed comes from `entropy.fill` rather than
/// `io.random`, whose contract permits a silent degrade (CONVENTIONS.md
/// §2.2). For X25519 the seed IS the secret key, so a weak draw here is a
/// weak identity/prekey/ephemeral/ratchet key with nothing to report it.
/// The retry loop is std's and is kept for the same reason std keeps it:
/// `generateDeterministic` rejects a seed whose public key is the identity
/// element, and the answer is another draw, not a failure.
///
/// This is the module's fail-closed key source and is deliberately NOT the
/// seam the KAT tests drive. Those pass their randomness in as a value —
/// `xeddsa.sign`'s `z` parameter — which is why `CONVENTIONS.md` §2.2 can
/// name signal's KAT seam an `io.random` exception without that exception
/// reaching any key minted here.
pub fn generateKeyPair(io: std.Io) X25519.KeyPair {
    var seed: [X25519.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    while (true) {
        entropy.fill(io, &seed);
        return X25519.KeyPair.generateDeterministic(seed) catch {
            @branchHint(.unlikely);
            continue;
        };
    }
}

// ── PreKeyBundle (what Bob publishes) — REAL codec ──────────────────────

/// What Bob publishes to the server for Alice to fetch (spec §
/// "Publishing keys"): his identity key, one signed prekey (plus its
/// signature and id), and OPTIONALLY one one-time prekey (plus its id) —
/// the server hands out (and deletes) one OPK per fetch until it runs out,
/// at which point `one_time_prekey`/`one_time_prekey_id` are `null` and
/// X3DH degrades gracefully to three DHs instead of four (spec explicitly
/// allows this, at a documented forward-secrecy cost for that one
/// session).
pub const PreKeyBundle = struct {
    identity_key: [key_length]u8,
    signed_prekey: [key_length]u8,
    signed_prekey_id: u32,
    signed_prekey_signature: xeddsa.Signature,
    one_time_prekey: ?[key_length]u8 = null,
    one_time_prekey_id: ?u32 = null,

    /// `identity_key(32) || signed_prekey(32) || signed_prekey_id(4 LE) ||
    /// signed_prekey_signature(64) || has_opk(1) || one_time_prekey_id(4
    /// LE, 0 if absent) || one_time_prekey(32, zero-filled if absent)`.
    pub const encoded_length: usize = key_length + key_length + 4 + signature_length + 1 + 4 + key_length; // 169

    pub const DecodeError = error{InvalidPreKeyBundle};

    pub fn toBytes(b: PreKeyBundle) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        var off: usize = 0;
        out[off..][0..key_length].* = b.identity_key;
        off += key_length;
        out[off..][0..key_length].* = b.signed_prekey;
        off += key_length;
        std.mem.writeInt(u32, out[off..][0..4], b.signed_prekey_id, .little);
        off += 4;
        out[off..][0..signature_length].* = b.signed_prekey_signature;
        off += signature_length;
        const has_opk = b.one_time_prekey != null;
        out[off] = @intFromBool(has_opk);
        off += 1;
        std.mem.writeInt(u32, out[off..][0..4], b.one_time_prekey_id orelse 0, .little);
        off += 4;
        out[off..][0..key_length].* = b.one_time_prekey orelse [_]u8{0} ** key_length;
        off += key_length;
        std.debug.assert(off == encoded_length);
        return out;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) DecodeError!PreKeyBundle {
        var off: usize = 0;
        const identity_key = bytes[off..][0..key_length].*;
        off += key_length;
        const signed_prekey = bytes[off..][0..key_length].*;
        off += key_length;
        const signed_prekey_id = std.mem.readInt(u32, bytes[off..][0..4], .little);
        off += 4;
        const signed_prekey_signature = bytes[off..][0..signature_length].*;
        off += signature_length;
        const has_opk_byte = bytes[off];
        off += 1;
        if (has_opk_byte > 1) return error.InvalidPreKeyBundle;
        const has_opk = has_opk_byte == 1;
        const opk_id = std.mem.readInt(u32, bytes[off..][0..4], .little);
        off += 4;
        const opk_bytes = bytes[off..][0..key_length].*;
        off += key_length;
        std.debug.assert(off == encoded_length);
        return .{
            .identity_key = identity_key,
            .signed_prekey = signed_prekey,
            .signed_prekey_id = signed_prekey_id,
            .signed_prekey_signature = signed_prekey_signature,
            .one_time_prekey = if (has_opk) opk_bytes else null,
            .one_time_prekey_id = if (has_opk) opk_id else null,
        };
    }
};

// ── InitialMessage (what Alice sends) — REAL codec ──────────────────────

/// What Alice sends Bob to complete the handshake (spec § "Sending the
/// initial message"): her identity + ephemeral public keys, which of
/// Bob's (signed / one-time) prekeys she used, and an opaque initial
/// ciphertext (see this file's module doc comment's "Part 2 boundary" —
/// this module neither produces nor interprets that ciphertext).
pub const InitialMessage = struct {
    identity_key: [key_length]u8,
    ephemeral_key: [key_length]u8,
    signed_prekey_id: u32,
    one_time_prekey_id: ?u32,
    ciphertext: []const u8,

    pub const DecodeError = error{InvalidInitialMessage} || std.mem.Allocator.Error;

    /// Fixed header size, NOT counting the variable-length `ciphertext`:
    /// `identity_key(32) || ephemeral_key(32) || signed_prekey_id(4 LE) ||
    /// has_opk(1) || one_time_prekey_id(4 LE) || ciphertext_len(4 LE)`.
    pub const header_length: usize = key_length + key_length + 4 + 1 + 4 + 4; // 77

    /// Caller owns the returned slice (`allocator.free`).
    pub fn toBytes(m: InitialMessage, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, header_length + m.ciphertext.len);
        var off: usize = 0;
        out[off..][0..key_length].* = m.identity_key;
        off += key_length;
        out[off..][0..key_length].* = m.ephemeral_key;
        off += key_length;
        std.mem.writeInt(u32, out[off..][0..4], m.signed_prekey_id, .little);
        off += 4;
        const has_opk = m.one_time_prekey_id != null;
        out[off] = @intFromBool(has_opk);
        off += 1;
        std.mem.writeInt(u32, out[off..][0..4], m.one_time_prekey_id orelse 0, .little);
        off += 4;
        std.mem.writeInt(u32, out[off..][0..4], @intCast(m.ciphertext.len), .little);
        off += 4;
        std.debug.assert(off == header_length);
        @memcpy(out[off..], m.ciphertext);
        return out;
    }

    /// Caller owns the returned `ciphertext` slice (`allocator.free`).
    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) DecodeError!InitialMessage {
        if (bytes.len < header_length) return error.InvalidInitialMessage;
        var off: usize = 0;
        const identity_key = bytes[off..][0..key_length].*;
        off += key_length;
        const ephemeral_key = bytes[off..][0..key_length].*;
        off += key_length;
        const signed_prekey_id = std.mem.readInt(u32, bytes[off..][0..4], .little);
        off += 4;
        const has_opk_byte = bytes[off];
        off += 1;
        if (has_opk_byte > 1) return error.InvalidInitialMessage;
        const has_opk = has_opk_byte == 1;
        const opk_id = std.mem.readInt(u32, bytes[off..][0..4], .little);
        off += 4;
        const ciphertext_len = std.mem.readInt(u32, bytes[off..][0..4], .little);
        off += 4;
        std.debug.assert(off == header_length);
        if (bytes.len - off != ciphertext_len) return error.InvalidInitialMessage;
        const ciphertext = try allocator.dupe(u8, bytes[off..]);
        return .{
            .identity_key = identity_key,
            .ephemeral_key = ephemeral_key,
            .signed_prekey_id = signed_prekey_id,
            .one_time_prekey_id = if (has_opk) opk_id else null,
            .ciphertext = ciphertext,
        };
    }

    pub fn deinit(m: InitialMessage, allocator: std.mem.Allocator) void {
        allocator.free(m.ciphertext);
    }
};

// ── DH + HKDF composition — REAL ────────────────────────────────────────

pub const AgreementError = error{
    /// One of the four `X25519.scalarmult` calls landed on the identity
    /// element (`std.crypto.errors.IdentityElementError`) — only possible
    /// with a maliciously/pathologically chosen (low-order) public key;
    /// never happens for honestly-generated keys.
    KeyAgreementFailed,
};

pub const Agreement = struct {
    shared_secret: [shared_secret_length]u8,
    associated_data: [associated_data_length]u8,
};

fn dh(secret_key: [key_length]u8, public_key: [key_length]u8) AgreementError![key_length]u8 {
    return X25519.scalarmult(secret_key, public_key) catch error.KeyAgreementFailed;
}

/// `SK = KDF(F || DH1 || DH2 || DH3 [|| DH4])` — shared by both
/// `initiateUnverified` and `respond` so the two sides can never drift
/// (one HKDF call site, not two independently-written ones).
fn deriveSharedSecret(dh1: [key_length]u8, dh2: [key_length]u8, dh3: [key_length]u8, dh4: ?[key_length]u8) [shared_secret_length]u8 {
    var km_buf: [f_constant.len + key_length * 4]u8 = undefined;
    var len: usize = 0;
    km_buf[len..][0..f_constant.len].* = f_constant;
    len += f_constant.len;
    km_buf[len..][0..key_length].* = dh1;
    len += key_length;
    km_buf[len..][0..key_length].* = dh2;
    len += key_length;
    km_buf[len..][0..key_length].* = dh3;
    len += key_length;
    if (dh4) |d4| {
        km_buf[len..][0..key_length].* = d4;
        len += key_length;
    }
    const km = km_buf[0..len];

    const salt = [_]u8{0} ** HkdfSha256.prk_length;
    const prk = HkdfSha256.extract(&salt, km);
    var sk: [shared_secret_length]u8 = undefined;
    HkdfSha256.expand(&sk, x3dh_info, prk);
    return sk;
}

/// `AD = Encode(IKA) || Encode(IKB)` (spec § "Sending the initial
/// message") — the raw 32-byte X25519 public keys, concatenated.
fn associatedData(ik_a_pub: [key_length]u8, ik_b_pub: [key_length]u8) [associated_data_length]u8 {
    var ad: [associated_data_length]u8 = undefined;
    ad[0..key_length].* = ik_a_pub;
    ad[key_length..].* = ik_b_pub;
    return ad;
}

pub const InitiateError = AgreementError || error{
    /// `initiate` only: `bob_bundle.signed_prekey_signature` failed
    /// `xeddsa.verify` under `bob_bundle.identity_key` — fail-closed, spec
    /// § "X3DH key agreement" step 2 ("Verifies the prekey signature").
    /// Never returned by `initiateUnverified`, which skips this check —
    /// see this file's module doc comment.
    SignedPreKeyVerificationFailed,
};

pub const InitiateOutput = struct {
    agreement: Agreement,
    /// Caller owns `message.ciphertext` (`message.deinit(allocator)`).
    message: InitialMessage,
};

/// Alice's side of X3DH, WITHOUT verifying `bob_bundle`'s XEdDSA
/// signature first — exists so the DH+HKDF agreement is testable in
/// isolation from `xeddsa.verify`. **Not the fail-closed entry point** —
/// real callers should use `initiate` (skipping verification breaks
/// X3DH's mutual authentication — see `SPEC.md`'s threat model).
///
/// Spec § "X3DH key agreement" steps 3-5 (verification, step 2, is
/// deliberately skipped here):
///
/// 1. Generate a fresh ephemeral keypair `EKA` (`X25519.KeyPair.generate(io)`).
/// 2. `DH1 = DH(IKA, SPKB)`, `DH2 = DH(EKA, IKB)`, `DH3 = DH(EKA, SPKB)`,
///    and `DH4 = DH(EKA, OPKB)` iff `bob_bundle.one_time_prekey` is set.
/// 3. `SK = KDF(F || DH1 || DH2 || DH3 [|| DH4])` (`deriveSharedSecret`).
/// 4. `AD = Encode(IKA) || Encode(IKB)` (`associatedData`).
/// 5. Package `(IKA_pub, EKA_pub, SPKB's id, OPKB's id if used,
///    initial_ciphertext)` into the `InitialMessage` Alice sends Bob.
pub fn initiateUnverified(
    allocator: std.mem.Allocator,
    alice_ik: IdentityKey,
    bob_bundle: PreKeyBundle,
    initial_ciphertext: []const u8,
    io: std.Io,
) (AgreementError || std.mem.Allocator.Error)!InitiateOutput {
    // `EKA` is single-use and feeds three of the four DHs — it is the only
    // secret Alice contributes to this session that is not her long-term
    // identity key, so it carries the run's forward secrecy on its own.
    const ek = generateKeyPair(io);

    const dh1 = try dh(alice_ik.secret_key, bob_bundle.signed_prekey);
    const dh2 = try dh(ek.secret_key, bob_bundle.identity_key);
    const dh3 = try dh(ek.secret_key, bob_bundle.signed_prekey);
    const dh4: ?[key_length]u8 = if (bob_bundle.one_time_prekey) |opk_pub|
        try dh(ek.secret_key, opk_pub)
    else
        null;

    const shared_secret = deriveSharedSecret(dh1, dh2, dh3, dh4);
    const ad = associatedData(alice_ik.public_key, bob_bundle.identity_key);

    const ciphertext_owned = try allocator.dupe(u8, initial_ciphertext);
    return .{
        .agreement = .{ .shared_secret = shared_secret, .associated_data = ad },
        .message = .{
            .identity_key = alice_ik.public_key,
            .ephemeral_key = ek.public_key,
            .signed_prekey_id = bob_bundle.signed_prekey_id,
            .one_time_prekey_id = if (bob_bundle.one_time_prekey != null) bob_bundle.one_time_prekey_id else null,
            .ciphertext = ciphertext_owned,
        },
    };
}

/// Alice's side of X3DH, FAIL-CLOSED (the entry point a real caller
/// should use): verifies `bob_bundle`'s XEdDSA signature under
/// `xeddsa.verify` first (spec § "X3DH key agreement" step 2) and only
/// then defers to `initiateUnverified`.
pub fn initiate(
    allocator: std.mem.Allocator,
    alice_ik: IdentityKey,
    bob_bundle: PreKeyBundle,
    initial_ciphertext: []const u8,
    io: std.Io,
) (InitiateError || std.mem.Allocator.Error)!InitiateOutput {
    if (!xeddsa.verify(bob_bundle.identity_key, &bob_bundle.signed_prekey, bob_bundle.signed_prekey_signature))
        return error.SignedPreKeyVerificationFailed;
    return initiateUnverified(allocator, alice_ik, bob_bundle, initial_ciphertext, io);
}

/// Bob's side of X3DH (spec § "Receiving the initial message" steps
/// 1-2): recomputes the SAME four DHs from Bob's own private material +
/// Alice's `InitialMessage`, landing on the identical `SK`/`AD`
/// `initiateUnverified` derived (X25519 DH is symmetric:
/// `DH(a_priv, b_pub) == DH(b_priv, a_pub)`, so Bob needs no data Alice
/// didn't already send).
///
/// `bob_opk` MUST be provided iff `alice_initial.one_time_prekey_id` is
/// non-null (the specific one-time prekey Alice's message names) —
/// callers look it up by id from local storage; a mismatch (Alice named
/// an id Bob no longer has, or Bob has one but Alice's message says
/// `null`) is a caller-side bug this function does not itself detect
/// (it only uses whichever of the two `?` values it is given — see
/// `SPEC.md` for the id-mismatch caveat a production integration must
/// check).
pub fn respond(
    bob_ik: IdentityKey,
    bob_spk: SignedPreKey,
    bob_opk: ?OneTimePreKey,
    alice_initial: InitialMessage,
) AgreementError!Agreement {
    const dh1 = try dh(bob_spk.key_pair.secret_key, alice_initial.identity_key);
    const dh2 = try dh(bob_ik.secret_key, alice_initial.ephemeral_key);
    const dh3 = try dh(bob_spk.key_pair.secret_key, alice_initial.ephemeral_key);
    const dh4: ?[key_length]u8 = if (bob_opk) |opk|
        try dh(opk.key_pair.secret_key, alice_initial.ephemeral_key)
    else
        null;

    const shared_secret = deriveSharedSecret(dh1, dh2, dh3, dh4);
    const ad = associatedData(alice_initial.identity_key, bob_ik.public_key);
    return .{ .shared_secret = shared_secret, .associated_data = ad };
}

/// Generates a fresh `SignedPreKey`: a new X25519 keypair plus Bob's
/// XEdDSA signature over its PUBLIC half, under `bob_ik` (spec: "SPK_B ...
/// signed ... with IK_B"). `z` is the 64 bytes of signing randomness
/// `xeddsa.sign` consumes — fill from `io.random`, like the callers in
/// `kat_test.zig` do.
///
/// Note the asymmetry between the two sources of randomness here, and that
/// it is deliberate: the KEYPAIR is drawn fail-closed below, while `z`
/// stays a caller-supplied parameter (XEdDSA tolerates a weak `z` — it is
/// hashed together with the secret scalar and the message, never used
/// alone — and passing it in is what makes the published vectors
/// reproducible).
pub fn generateSignedPreKey(bob_ik: IdentityKey, id: u32, z: xeddsa.RandomData, io: std.Io) SignedPreKey {
    // `SPKB` is medium-term: it signs Bob's bundle for every session opened
    // between two rotations, so one weak draw compromises all of them.
    const kp = generateKeyPair(io);
    const sig = xeddsa.sign(bob_ik.secret_key, &kp.public_key, z);
    return .{ .key_pair = kp, .signature = sig, .id = id };
}

// ── tests ────────────────────────────────────────────────────────────

test "encoded_length / header_length constants match this file's wire layout" {
    try std.testing.expectEqual(@as(usize, 169), PreKeyBundle.encoded_length);
    try std.testing.expectEqual(@as(usize, 77), InitialMessage.header_length);
}

test "f_constant is 32 bytes of 0xFF (X25519 domain-separation prefix, spec sec KDF)" {
    try std.testing.expectEqual(@as(usize, 32), f_constant.len);
    for (f_constant) |b| try std.testing.expectEqual(@as(u8, 0xFF), b);
}
