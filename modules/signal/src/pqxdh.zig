// SPDX-License-Identifier: MIT

//! PQXDH — Signal's post-quantum extended triple Diffie-Hellman
//! (<https://signal.org/docs/specifications/pqxdh/>), Part 3 of this module's
//! arc and the successor to `x3dh.zig`.
//!
//! PQXDH is X3DH plus one KEM encapsulation against a **signed** post-quantum
//! prekey Bob published in advance. The point is asynchrony: an attacker who
//! records today's traffic and owns a quantum computer later still cannot
//! recover `SK`, because `SK` also depends on a shared secret that never
//! travelled as a Diffie-Hellman public value. Everything else — the three or
//! four X25519 agreements, the `0xFF` prefix, the HKDF, the associated data —
//! is X3DH's, and this file deliberately mirrors `x3dh.zig` structurally so
//! the diff between the two protocols is readable.
//!
//! ## Two things a reader should know before trusting this file
//!
//! **1. The published spec still names Kyber, and that is not what runs.**
//! The PQXDH document's parameter table says `pqkem` is "e.g.
//! Crystals-Kyber-1024" and its reference for that is the *initial public
//! draft* of FIPS 203, not the final standard. Round-3 Kyber and FIPS-203
//! ML-KEM are **not wire-compatible** (different FO transform, different
//! domain separation, a fixed matrix index); Signal's own libsignal keeps
//! `Kyber1024` and `MLKEM1024` as separate key types, which is itself the
//! evidence that they do not interoperate. This file implements **ML-KEM-1024
//! (FIPS 203 final)** via `std.crypto.kem.ml_kem`, which is what deployments
//! use, and says so rather than claiming to be "the spec's KEM".
//!
//! **2. There are no published PQXDH test vectors.** Neither the spec page nor
//! libsignal publishes byte-exact known-answer data for the composed
//! agreement — checked 2026-08-22. So the anchoring here is layered rather
//! than end-to-end: `xeddsa` carries libsignal's own published vector, and the
//! composition itself is checked against an independent HKDF implementation
//! (`scripts/pqxdh-kdf-check.py`, whose output is pinned in
//! `interop_vectors.zig`). What is NOT claimed is byte-compatibility with
//! Signal's servers: like `x3dh.zig`, this file uses its own `info` string,
//! which the spec explicitly leaves application-specific.
//!
//! ⚠ **The KEM itself is the weakest link in that chain, and this file used to
//! overstate it.** It claimed ML-KEM-1024 was "anchored by `std`'s FIPS 203
//! vectors". It is not: `std.crypto.kem.ml_kem`'s three `NIST KAT test`
//! blocks are all `d00.Kyber512/768/1024` — the round-3 namespace this file
//! spends a paragraph explaining is *not* what it implements. `nist.MLKem1024`
//! has only `"Test happy flow"`, a `generateDeterministic → encapsDeterministic
//! → decaps` self round trip, which is the self-consistency class this module
//! declines to call an anchor anywhere else. Closing it means bringing in NIST
//! ACVP vectors for ML-KEM, the way `slhdsa` did; until then the KEM is
//! unanchored and this comment says so.

const std = @import("std");
const entropy = @import("entropy");
const x3dh = @import("x3dh.zig");
const xeddsa = @import("xeddsa.zig");
const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// The KEM this file implements. See the module doc comment: the spec text
/// says Kyber-1024, deployments use ML-KEM-1024, and the two do not
/// interoperate.
pub const Kem = std.crypto.kem.ml_kem.MLKem1024;

pub const key_length = x3dh.key_length;
pub const shared_secret_length = x3dh.shared_secret_length;
pub const signature_length = x3dh.signature_length;

/// ML-KEM-1024 sizes, named so wire-layout arithmetic below reads as sizes
/// rather than as magic numbers.
pub const kem_public_length: usize = Kem.PublicKey.encoded_length; // 1568
pub const kem_ciphertext_length: usize = Kem.ciphertext_length; // 1568
pub const kem_shared_length: usize = Kem.shared_length; // 32

/// `AD = Encode(IKA) || Encode(IKB) || Encode(PQPKB)`.
///
/// The third term is REQUIRED here and is easy to get wrong. The spec says
/// Alice appends the KEM public key to the associated data "if the KEM
/// ciphertext does not already bind" it. ML-KEM's ciphertext does not: it is
/// an encryption of a message under the public key, and nothing in it commits
/// to which public key that was. Omitting `Encode(PQPKB)` would let an
/// attacker who can swap Bob's published KEM prekey do so without the
/// authenticated data changing.
pub const associated_data_length: usize = key_length * 2 + kem_public_length;

/// Same 32-byte `0xFF` domain-separation prefix as X3DH (spec § "KDF"; 57
/// bytes for curve448, not implemented here).
pub const f_constant = x3dh.f_constant;

/// This module's `info` for the final HKDF-Expand, distinct from
/// `x3dh.x3dh_info` so a PQXDH session and an X3DH session can never derive
/// the same `SK` from the same inputs. The spec leaves `info` application-
/// specific and recommends it identify the protocol, curve, hash and KEM:
/// this one does, including the KEM the file actually implements.
pub const pqxdh_info = "zig-libs/signal/pqxdh/v1_CURVE25519_SHA-256_ML-KEM-1024";

pub const IdentityKey = x3dh.IdentityKey;
pub const EphemeralKey = x3dh.EphemeralKey;
pub const SignedPreKey = x3dh.SignedPreKey;
pub const OneTimePreKey = x3dh.OneTimePreKey;

/// Bob's post-quantum prekey: an ML-KEM keypair plus Bob's XEdDSA signature
/// over its public half.
///
/// Unlike a one-time *curve* prekey, which the spec leaves unsigned, EVERY
/// KEM prekey is signed — last-resort and one-time alike. That asymmetry is
/// not an oversight in the spec: a curve prekey's contribution is
/// authenticated by the DH with Bob's identity key, and a KEM prekey's is
/// not, so the signature is the only thing binding it to Bob.
pub const KemPreKey = struct {
    key_pair: Kem.KeyPair,
    signature: xeddsa.Signature,
    id: u32,
    /// A last-resort prekey is reused until Bob rotates it; a one-time prekey
    /// is deleted after a single use. The distinction is Bob's bookkeeping,
    /// not a wire difference, and it is carried here so a caller's storage
    /// layer cannot lose it.
    last_resort: bool,
};

pub const AgreementError = x3dh.AgreementError;

pub const Agreement = struct {
    shared_secret: [shared_secret_length]u8,
    /// `Encode(IKA) || Encode(IKB) || Encode(PQPKB)` — the associated data for
    /// the INITIAL message. It is 1632 bytes because of the third term.
    associated_data: [associated_data_length]u8,

    /// The first 64 bytes: `Encode(IKA) || Encode(IKB)`, which is what a
    /// post-PQXDH Double Ratchet uses as its per-message associated data.
    ///
    /// The two are deliberately different lengths and it is not an oversight
    /// on either side. The KEM prekey has to be bound where an attacker could
    /// substitute it — the initial message, the only place it is used — and
    /// binding it into every subsequent ratchet message would add 1568 bytes
    /// of associated data per message to protect a key that no longer
    /// participates. `ratchet.State.initAlice`/`initBob` take exactly these 64
    /// bytes, so a consumer wiring PQXDH to the ratchet passes this rather
    /// than `associated_data`.
    pub fn ratchetAssociatedData(self: Agreement) [x3dh.associated_data_length]u8 {
        return self.associated_data[0..x3dh.associated_data_length].*;
    }
};

/// What Bob publishes. The curve half is exactly `x3dh.PreKeyBundle`'s; the
/// KEM half is new.
pub const PreKeyBundle = struct {
    identity_key: [key_length]u8,
    signed_prekey: [key_length]u8,
    signed_prekey_id: u32,
    signed_prekey_signature: xeddsa.Signature,
    one_time_prekey: ?[key_length]u8,
    one_time_prekey_id: u32,
    kem_prekey: [kem_public_length]u8,
    kem_prekey_id: u32,
    kem_prekey_signature: xeddsa.Signature,
};

/// What Alice sends. `kem_ciphertext` is the encapsulation against
/// `PreKeyBundle.kem_prekey`; `kem_prekey_id` names which of Bob's KEM
/// prekeys it was, so Bob can find the matching secret.
pub const InitialMessage = struct {
    identity_key: [key_length]u8,
    ephemeral_key: [key_length]u8,
    signed_prekey_id: u32,
    one_time_prekey_id: ?u32,
    kem_prekey_id: u32,
    kem_ciphertext: [kem_ciphertext_length]u8,
    /// Opaque, caller-supplied — this file carries it and never interprets
    /// it, exactly as `x3dh.InitialMessage.ciphertext` does.
    ciphertext: []const u8,

    /// Frees `ciphertext`, which `initiate` allocated. The same shape as
    /// `x3dh.InitialMessage.deinit`; `InitiateOutput`'s doc comment named this
    /// method before it existed, so a caller following the documentation did
    /// not compile.
    pub fn deinit(m: InitialMessage, allocator: std.mem.Allocator) void {
        allocator.free(m.ciphertext);
    }
};

fn dh(secret_key: [key_length]u8, public_key: [key_length]u8) AgreementError![key_length]u8 {
    return X25519.scalarmult(secret_key, public_key) catch error.KeyAgreementFailed;
}

/// `SK = KDF(F || DH1 || DH2 || DH3 [|| DH4] || SS)`.
///
/// Note where `SS` goes: **after** every Diffie-Hellman output, including the
/// optional `DH4`. Putting it anywhere else still produces a 32-byte key that
/// both sides agree on if both sides make the same mistake, which is why the
/// order is pinned by a test against an independent implementation rather
/// than by a round trip.
fn deriveSharedSecret(
    dh1: [key_length]u8,
    dh2: [key_length]u8,
    dh3: [key_length]u8,
    dh4: ?[key_length]u8,
    ss: [kem_shared_length]u8,
) [shared_secret_length]u8 {
    // The buffer holds `F || DH1..DH4 || SS` — every secret of the handshake,
    // including the one whose leak deletes the post-quantum property. It costs
    // one instruction to not leave it on the stack.
    var km_buf: [f_constant.len + key_length * 4 + kem_shared_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &km_buf);
    var len: usize = 0;
    km_buf[len..][0..f_constant.len].* = f_constant;
    len += f_constant.len;
    inline for (.{ dh1, dh2, dh3 }) |d| {
        km_buf[len..][0..key_length].* = d;
        len += key_length;
    }
    if (dh4) |d4| {
        km_buf[len..][0..key_length].* = d4;
        len += key_length;
    }
    km_buf[len..][0..kem_shared_length].* = ss;
    len += kem_shared_length;

    const salt = [_]u8{0} ** HkdfSha256.prk_length;
    const prk = HkdfSha256.extract(&salt, km_buf[0..len]);
    var sk: [shared_secret_length]u8 = undefined;
    HkdfSha256.expand(&sk, pqxdh_info, prk);
    return sk;
}

fn associatedData(
    ik_a_pub: [key_length]u8,
    ik_b_pub: [key_length]u8,
    kem_pub: [kem_public_length]u8,
) [associated_data_length]u8 {
    var ad: [associated_data_length]u8 = undefined;
    ad[0..key_length].* = ik_a_pub;
    ad[key_length..][0..key_length].* = ik_b_pub;
    ad[key_length * 2 ..][0..kem_public_length].* = kem_pub;
    return ad;
}

pub const InitiateError = AgreementError || error{
    /// `bob_bundle.signed_prekey_signature` did not verify under the bundle's
    /// identity key.
    SignedPreKeyVerificationFailed,
    /// `bob_bundle.kem_prekey_signature` did not verify. Separate from the
    /// curve failure above on purpose: they are different keys with different
    /// rotation schedules, and a caller triaging a rejected bundle wants to
    /// know which one is stale.
    KemPreKeyVerificationFailed,
    /// `bob_bundle.kem_prekey` is not a valid ML-KEM-1024 public key.
    InvalidKemPreKey,
};

pub const InitiateOutput = struct {
    agreement: Agreement,
    /// Caller owns `message.ciphertext` (`message.deinit(allocator)`).
    message: InitialMessage,
};

/// Alice's side, WITHOUT verifying Bob's two signatures — exists so the
/// agreement is testable in isolation, exactly as `x3dh.initiateUnverified`
/// is. **Not the entry point a real caller should use**: skipping either
/// signature breaks the authentication PQXDH exists to provide, and skipping
/// the KEM one specifically lets an attacker substitute a KEM prekey they
/// hold the secret for, which removes the post-quantum protection entirely
/// while leaving every other check passing.
pub fn initiateUnverified(
    allocator: std.mem.Allocator,
    alice_ik: IdentityKey,
    bob_bundle: PreKeyBundle,
    initial_ciphertext: []const u8,
    io: std.Io,
) (InitiateError || std.mem.Allocator.Error)!InitiateOutput {
    const ek = x3dh.generateKeyPair(io);

    const dh1 = try dh(alice_ik.secret_key, bob_bundle.signed_prekey);
    const dh2 = try dh(ek.secret_key, bob_bundle.identity_key);
    const dh3 = try dh(ek.secret_key, bob_bundle.signed_prekey);
    const dh4: ?[key_length]u8 = if (bob_bundle.one_time_prekey) |opk_pub|
        try dh(ek.secret_key, opk_pub)
    else
        null;

    const kem_pk = Kem.PublicKey.fromBytes(&bob_bundle.kem_prekey) catch
        return error.InvalidKemPreKey;
    // `encaps(io)` would draw the encapsulation message from `io.random`. That
    // message IS the post-quantum secret — `SS` is its hash — so it goes
    // through the fail-closed source, same as every other secret here.
    var enc_seed: [Kem.encaps_seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &enc_seed);
    entropy.fill(io, &enc_seed);
    const enc = kem_pk.encapsDeterministic(&enc_seed);

    const shared_secret = deriveSharedSecret(dh1, dh2, dh3, dh4, enc.shared_secret);
    const ad = associatedData(alice_ik.public_key, bob_bundle.identity_key, bob_bundle.kem_prekey);

    const ciphertext_owned = try allocator.dupe(u8, initial_ciphertext);
    return .{
        .agreement = .{ .shared_secret = shared_secret, .associated_data = ad },
        .message = .{
            .identity_key = alice_ik.public_key,
            .ephemeral_key = ek.public_key,
            .signed_prekey_id = bob_bundle.signed_prekey_id,
            .one_time_prekey_id = if (bob_bundle.one_time_prekey != null) bob_bundle.one_time_prekey_id else null,
            .kem_prekey_id = bob_bundle.kem_prekey_id,
            .kem_ciphertext = enc.ciphertext,
            .ciphertext = ciphertext_owned,
        },
    };
}

/// Alice's side, fail-closed: both of Bob's signatures are verified before
/// any key material is derived.
pub fn initiate(
    allocator: std.mem.Allocator,
    alice_ik: IdentityKey,
    bob_bundle: PreKeyBundle,
    initial_ciphertext: []const u8,
    io: std.Io,
) (InitiateError || std.mem.Allocator.Error)!InitiateOutput {
    if (!xeddsa.verify(bob_bundle.identity_key, &bob_bundle.signed_prekey, bob_bundle.signed_prekey_signature))
        return error.SignedPreKeyVerificationFailed;
    if (!xeddsa.verify(bob_bundle.identity_key, &bob_bundle.kem_prekey, bob_bundle.kem_prekey_signature))
        return error.KemPreKeyVerificationFailed;
    return initiateUnverified(allocator, alice_ik, bob_bundle, initial_ciphertext, io);
}

pub const RespondError = AgreementError || error{
    /// **Currently unreachable, and a caller must not read it as validation.**
    /// FIPS 203's implicit rejection means decapsulation has no failure mode:
    /// `std`'s `decaps` returns unconditionally on both its branches, `cmov`ing
    /// to `J(z‖c)` when the re-encryption disagrees, so its inferred error set
    /// is empty and the `catch` below is dead. Every 1568-byte string
    /// decapsulates to *some* secret.
    ///
    /// The arm is kept rather than deleted so a future `std` that does gain an
    /// error has somewhere to land. What detects a substituted ciphertext is
    /// not this error but the mismatched `SK`, which surfaces as an AEAD
    /// failure in whatever the caller encrypts under it — `respond` succeeding
    /// says nothing about the ciphertext being genuine.
    KemDecapsulationFailed,
};

/// Bob's side: recompute the same three or four X25519 agreements, decapsulate
/// Alice's ciphertext under the KEM prekey she named, and land on the same
/// `SK`/`AD`.
///
/// `bob_kem` must be the prekey whose id is `alice_initial.kem_prekey_id`, and
/// `bob_opk` must be present exactly when `alice_initial.one_time_prekey_id`
/// is — the same caller-side lookup contract `x3dh.respond` documents.
pub fn respond(
    bob_ik: IdentityKey,
    bob_spk: SignedPreKey,
    bob_opk: ?OneTimePreKey,
    bob_kem: KemPreKey,
    alice_initial: InitialMessage,
) RespondError!Agreement {
    const dh1 = try dh(bob_spk.key_pair.secret_key, alice_initial.identity_key);
    const dh2 = try dh(bob_ik.secret_key, alice_initial.ephemeral_key);
    const dh3 = try dh(bob_spk.key_pair.secret_key, alice_initial.ephemeral_key);
    const dh4: ?[key_length]u8 = if (bob_opk) |opk|
        try dh(opk.key_pair.secret_key, alice_initial.ephemeral_key)
    else
        null;

    const ss = bob_kem.key_pair.secret_key.decaps(&alice_initial.kem_ciphertext) catch
        return error.KemDecapsulationFailed;

    const shared_secret = deriveSharedSecret(dh1, dh2, dh3, dh4, ss);
    const ad = associatedData(
        alice_initial.identity_key,
        bob_ik.public_key,
        bob_kem.key_pair.public_key.toBytes(),
    );
    return .{ .shared_secret = shared_secret, .associated_data = ad };
}

/// A fresh ML-KEM keypair drawn from this module's fail-closed entropy source.
///
/// Body-identical to `Kem.KeyPair.generate`, with the one substitution
/// `x3dh.generateKeyPair` already makes for X25519: the seed comes from
/// `entropy.fill` (→ `io.randomSecure`, which panics rather than degrade)
/// instead of `io.random`, whose contract permits a silent degrade
/// (CONVENTIONS.md §2.2). The stakes are higher here than for a curve key,
/// not lower: this seed becomes a LONG-LIVED, signed prekey — a last-resort
/// one is reused until Bob rotates it — and it carries the entire
/// post-quantum property. A weak draw leaves every Diffie-Hellman strong and
/// silently reduces `SK` to classical X3DH material, which is precisely the
/// failure this file exists to prevent, with nothing to report it.
///
/// The retry loop is std's, kept for std's reason: `generateDeterministic`
/// rejects some seeds and the answer is another draw, not a failure.
fn generateKemKeyPair(io: std.Io) Kem.KeyPair {
    var seed: [Kem.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    while (true) {
        return Kem.KeyPair.generateDeterministic(blk: {
            entropy.fill(io, &seed);
            break :blk seed;
        }) catch {
            @branchHint(.unlikely);
            continue;
        };
    }
}

/// Generate a fresh KEM prekey and sign its public half under Bob's identity
/// key. `z` is XEdDSA's signing randomness, passed in for the same reason
/// `x3dh.generateSignedPreKey` takes it: it makes published vectors
/// reproducible, and XEdDSA hashes it together with the secret scalar rather
/// than using it alone.
pub fn generateKemPreKey(
    bob_ik: IdentityKey,
    id: u32,
    last_resort: bool,
    z: xeddsa.RandomData,
    io: std.Io,
) KemPreKey {
    const kp = generateKemKeyPair(io);
    const pk_bytes = kp.public_key.toBytes();
    return .{
        .key_pair = kp,
        .signature = xeddsa.sign(bob_ik.secret_key, &pk_bytes, z),
        .id = id,
        .last_resort = last_resort,
    };
}

// ── tests ────────────────────────────────────────────────────────────

const testing = std.testing;
const interop = @import("interop_vectors.zig");

fn hexEq(want_hex: []const u8, got: []const u8) !void {
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, want_hex);
    try testing.expectEqualSlices(u8, &want, got);
}

test "SK matches an independent implementation of the KDF chain, with and without DH4" {
    // The anchor is `scripts/pqxdh-kdf-check.py` — see `interop_vectors.zig`
    // for why this is a second implementation rather than the protocol
    // authors' own vectors, and what that does and does not buy.
    const d1: [32]u8 = @splat(1);
    const d2: [32]u8 = @splat(2);
    const d3: [32]u8 = @splat(3);
    const d4: [32]u8 = @splat(4);
    const ss: [32]u8 = @splat(5);

    try hexEq(interop.pqxdh_kdf.with_one_time_prekey, &deriveSharedSecret(d1, d2, d3, d4, ss));
    try hexEq(interop.pqxdh_kdf.without_one_time_prekey, &deriveSharedSecret(d1, d2, d3, null, ss));
}

test "the KEM secret goes LAST: the swapped-order value is never produced" {
    // A round trip cannot catch a misplaced `SS` — Alice and Bob would agree
    // on the wrong answer together. This pins the specific wrong answer.
    const d1: [32]u8 = @splat(1);
    const d2: [32]u8 = @splat(2);
    const d3: [32]u8 = @splat(3);
    const d4: [32]u8 = @splat(4);
    const ss: [32]u8 = @splat(5);
    const got = deriveSharedSecret(d1, d2, d3, d4, ss);

    var swapped: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&swapped, interop.pqxdh_kdf.ss_and_dh3_swapped);
    try testing.expect(!std.mem.eql(u8, &swapped, &got));
}

test "PQXDH derives a different SK than X3DH would from the same curve material" {
    // The `info` strings differ, so a session that negotiated PQXDH and one
    // that negotiated X3DH cannot land on the same root key even if every
    // Diffie-Hellman input matched. Cross-protocol key reuse is the failure
    // this prevents; without distinct `info` values it would be invisible.
    try testing.expect(!std.mem.eql(u8, pqxdh_info, x3dh.x3dh_info));
}

test "associated data binds Bob's KEM prekey, not just the two identity keys" {
    // ML-KEM's ciphertext does not commit to the public key it was produced
    // under, so `Encode(PQPKB)` in AD is what stops a swapped KEM prekey from
    // going unnoticed. Two AD values that differ ONLY in the KEM key must
    // differ.
    const ik_a: [32]u8 = @splat(0xA1);
    const ik_b: [32]u8 = @splat(0xB2);
    var kem1: [kem_public_length]u8 = @splat(0x11);
    var kem2: [kem_public_length]u8 = @splat(0x11);
    kem2[kem_public_length - 1] = 0x12;

    const ad1 = associatedData(ik_a, ik_b, kem1);
    const ad2 = associatedData(ik_a, ik_b, kem2);
    try testing.expect(!std.mem.eql(u8, &ad1, &ad2));
    try testing.expectEqual(@as(usize, 32 + 32 + 1568), associated_data_length);
    try testing.expectEqualSlices(u8, &ik_a, ad1[0..32]);
    try testing.expectEqualSlices(u8, &ik_b, ad1[32..64]);
    try testing.expectEqualSlices(u8, &kem1, ad1[64..]);
}

test "ML-KEM-1024 wire sizes are the FIPS 203 ones this file's layout assumes" {
    try testing.expectEqual(@as(usize, 1568), kem_public_length);
    try testing.expectEqual(@as(usize, 1568), kem_ciphertext_length);
    try testing.expectEqual(@as(usize, 32), kem_shared_length);
}

test "end to end: Alice initiates, Bob responds, both land on the same SK and AD" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bob_ik = x3dh.generateKeyPair(io);
    const alice_ik = x3dh.generateKeyPair(io);
    const z: xeddsa.RandomData = @splat(0x77);
    const spk = x3dh.generateSignedPreKey(bob_ik, 7, z, io);
    const kem = generateKemPreKey(bob_ik, 42, true, z, io);
    const opk_kp = x3dh.generateKeyPair(io);
    const opk: OneTimePreKey = .{ .key_pair = opk_kp, .id = 9 };

    const bundle: PreKeyBundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = spk.key_pair.public_key,
        .signed_prekey_id = spk.id,
        .signed_prekey_signature = spk.signature,
        .one_time_prekey = opk_kp.public_key,
        .one_time_prekey_id = opk.id,
        .kem_prekey = kem.key_pair.public_key.toBytes(),
        .kem_prekey_id = kem.id,
        .kem_prekey_signature = kem.signature,
    };

    const out = try initiate(testing.allocator, alice_ik, bundle, "hello", io);
    defer testing.allocator.free(out.message.ciphertext);

    const bob = try respond(bob_ik, spk, opk, kem, out.message);
    try testing.expectEqualSlices(u8, &out.agreement.shared_secret, &bob.shared_secret);
    try testing.expectEqualSlices(u8, &out.agreement.associated_data, &bob.associated_data);
    try testing.expectEqual(kem.id, out.message.kem_prekey_id);
    try testing.expectEqual(@as(?u32, opk.id), out.message.one_time_prekey_id);
}

test "fail-closed: a tampered KEM prekey signature is refused, and names WHICH key failed" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bob_ik = x3dh.generateKeyPair(io);
    const alice_ik = x3dh.generateKeyPair(io);
    const z: xeddsa.RandomData = @splat(0x77);
    const spk = x3dh.generateSignedPreKey(bob_ik, 7, z, io);
    const kem = generateKemPreKey(bob_ik, 42, true, z, io);

    var bundle: PreKeyBundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = spk.key_pair.public_key,
        .signed_prekey_id = spk.id,
        .signed_prekey_signature = spk.signature,
        .one_time_prekey = null,
        .one_time_prekey_id = 0,
        .kem_prekey = kem.key_pair.public_key.toBytes(),
        .kem_prekey_id = kem.id,
        .kem_prekey_signature = kem.signature,
    };
    bundle.kem_prekey_signature[0] +%= 1;

    try testing.expectError(
        error.KemPreKeyVerificationFailed,
        initiate(testing.allocator, alice_ik, bundle, "hello", io),
    );

    // The curve signature is still good, so the two failures are distinguished
    // rather than collapsed into one "bad bundle".
    bundle.kem_prekey_signature = kem.signature;
    bundle.signed_prekey_signature[0] +%= 1;
    try testing.expectError(
        error.SignedPreKeyVerificationFailed,
        initiate(testing.allocator, alice_ik, bundle, "hello", io),
    );
}

test "a substituted KEM prekey yields a DIFFERENT SK, which is how the swap is caught" {
    // ML-KEM has implicit rejection: decapsulating under the wrong secret key
    // succeeds and returns *a* shared secret. So the defence is not an error
    // from `decaps` -- it is that the resulting SK differs, and the first AEAD
    // under it fails. Worth a test precisely because the absence of an error
    // here looks like a missing check.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bob_ik = x3dh.generateKeyPair(io);
    const alice_ik = x3dh.generateKeyPair(io);
    const z: xeddsa.RandomData = @splat(0x77);
    const spk = x3dh.generateSignedPreKey(bob_ik, 7, z, io);
    const kem = generateKemPreKey(bob_ik, 42, true, z, io);
    const other_kem = generateKemPreKey(bob_ik, 43, false, z, io);

    const bundle: PreKeyBundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = spk.key_pair.public_key,
        .signed_prekey_id = spk.id,
        .signed_prekey_signature = spk.signature,
        .one_time_prekey = null,
        .one_time_prekey_id = 0,
        .kem_prekey = kem.key_pair.public_key.toBytes(),
        .kem_prekey_id = kem.id,
        .kem_prekey_signature = kem.signature,
    };

    const out = try initiate(testing.allocator, alice_ik, bundle, "hello", io);
    defer testing.allocator.free(out.message.ciphertext);

    const wrong = try respond(bob_ik, spk, null, other_kem, out.message);
    try testing.expect(!std.mem.eql(u8, &out.agreement.shared_secret, &wrong.shared_secret));
}

// ── the entropy seam (audit 2026-09-01) ──────────────────────────────────────
//
// `CONVENTIONS.md` §2.2: anything that becomes a key or ephemeral key material
// is drawn with `entropy.fill`/`io.randomSecure`, never `io.random`, whose
// contract permits a silent degrade. `x3dh.generateKeyPair` was moved to the
// fail-closed source on 2026-08-13 for exactly this reason; the two ML-KEM
// draws added with PQXDH reached `io.random` through std's convenience
// wrappers (`Kem.KeyPair.generate` / `PublicKey.encaps`) and inherited nothing
// of that decision. A weak draw there leaves every Diffie-Hellman strong and
// silently reduces `SK` to classical X3DH material — the exact failure this
// file exists to prevent, with nothing to report it.

/// An `Io` whose `random` has degraded to a constant, with `randomSecure` left
/// intact. Same shape as `sealedbox`'s KAT harness: copy the vtable, replace
/// one slot.
fn degradedRandom(_: ?*anyopaque, buffer: []u8) void {
    @memset(buffer, 0);
}

fn degradedIo(io: std.Io, vt: *std.Io.VTable) std.Io {
    vt.* = io.vtable.*;
    vt.random = degradedRandom;
    return .{ .userdata = io.userdata, .vtable = vt };
}

test "a degraded io.random cannot reach any PQXDH secret" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    var vt: std.Io.VTable = undefined;
    const io = degradedIo(threaded.io(), &vt);

    // CONTROL. Under the same degraded `io`, the module's existing curve-key
    // source still produces distinct keys — so a collision below is a
    // statement about this file, not about a broken harness.
    const c1 = x3dh.generateKeyPair(io);
    const c2 = x3dh.generateKeyPair(io);
    try testing.expect(!std.mem.eql(u8, &c1.public_key, &c2.public_key));

    const bob_ik = x3dh.generateKeyPair(io);
    const alice_ik = x3dh.generateKeyPair(io);
    const z: xeddsa.RandomData = @splat(0x77);
    const spk = x3dh.generateSignedPreKey(bob_ik, 7, z, io);

    // 1. Bob's ML-KEM prekey is long-lived and, when `last_resort`, reused
    //    until he rotates it. Two draws must not collide.
    const k1 = generateKemPreKey(bob_ik, 1, true, z, io);
    const k2 = generateKemPreKey(bob_ik, 2, true, z, io);
    try testing.expect(!std.mem.eql(u8, &k1.key_pair.public_key.toBytes(), &k2.key_pair.public_key.toBytes()));

    // 2. The encapsulation message determines `SS`. Two handshakes against the
    //    same bundle must not produce the same ciphertext — if they do, `SS`
    //    is derivable from Bob's PUBLIC prekey alone.
    const bundle: PreKeyBundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = spk.key_pair.public_key,
        .signed_prekey_id = spk.id,
        .signed_prekey_signature = spk.signature,
        .one_time_prekey = null,
        .one_time_prekey_id = 0,
        .kem_prekey = k1.key_pair.public_key.toBytes(),
        .kem_prekey_id = k1.id,
        .kem_prekey_signature = k1.signature,
    };
    const a = try initiate(testing.allocator, alice_ik, bundle, "hi", io);
    defer testing.allocator.free(a.message.ciphertext);
    const b = try initiate(testing.allocator, alice_ik, bundle, "hi", io);
    defer testing.allocator.free(b.message.ciphertext);
    try testing.expect(!std.mem.eql(u8, &a.message.kem_ciphertext, &b.message.kem_ciphertext));
    try testing.expect(!std.mem.eql(u8, &a.agreement.shared_secret, &b.agreement.shared_secret));
}
