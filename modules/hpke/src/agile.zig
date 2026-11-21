// SPDX-License-Identifier: MIT
//! Runtime-agile HPKE: the suite (KEM, KDF, AEAD) is a run-time `Suite`
//! value built from the registered ids, the way Go 1.26 `crypto/hpke`
//! (`NewKEM`/`NewKDF`/`NewAEAD` by id, `NewSender`/`NewRecipient`),
//! BoringSSL's `EVP_HPKE_*` and hpke-js pick it — for a protocol that
//! negotiates the suite on the wire (ECH, MLS, OHTTP key configs).
//!
//! A separate layer over the comptime API, not a replacement: every
//! cryptographic step is the comptime entry point of the KEM / key schedule /
//! `Context` this value selects (`dhkem`, `pq`, `schedule.keySchedule`,
//! `schedule.Context.seal`/`open`/`exportSecret`), dispatched by a `switch`
//! over the supported ids. Nothing here is compiled into a program that does
//! not reference `hpke.agile` (Zig analyses only what is referenced). The
//! top-level functions here (`setupS`, `generateKeyPair`, …) dispatch over
//! every KEM, KDF and AEAD of the module; `Agile(.{ .kems = …, .kdfs = …,
//! .aeads = … })` is the same API over a subset, so a program that accepts
//! only the suites it negotiates links only those (an id outside the subset
//! is `error.UnsupportedSuite`). SPEC.md § "Runtime-agile suites" has the
//! measured sizes.
//!
//! The dispatch is per component, not per suite: the KEM step is one switch
//! over 11 KEMs, the key schedule one instantiation per (KDF, AEAD) pair
//! (7 × 4), `seal`/`open` one per AEAD, `exportSecret` one per KDF — no
//! KEM × KDF × AEAD product.
//!
//! Modes: all four for the DHKEMs; base and psk for the ML-KEM and hybrid
//! KEMs (draft-ietf-hpke-pq defines no AuthEncap for them), as the comptime
//! API.

const std = @import("std");
const aesgcm = @import("aesgcm");
const chachapoly = @import("chachapoly");
const suite = @import("suite.zig");
const dhkem = @import("dhkem.zig");
const pq = @import("pq.zig");
const kdf = @import("kdf.zig");
const schedule = @import("schedule.zig");
const burn = @import("burn.zig");

pub const KemId = suite.KemId;
pub const KdfId = suite.KdfId;
pub const AeadId = suite.AeadId;
pub const Mode = suite.Mode;

/// Every KEM this module implements, in `KeyPair`'s field order.
pub const all_kems = [_]KemId{
    .dhkem_p256_hkdf_sha256,
    .dhkem_p384_hkdf_sha384,
    .dhkem_p521_hkdf_sha512,
    .dhkem_x25519_hkdf_sha256,
    .dhkem_x448_hkdf_sha512,
    .ml_kem_512,
    .ml_kem_768,
    .ml_kem_1024,
    .mlkem768_p256,
    .mlkem1024_p384,
    .mlkem768_x25519,
};

pub const all_kdfs = [_]KdfId{ .hkdf_sha256, .hkdf_sha384, .hkdf_sha512, .shake128, .shake256, .turboshake128, .turboshake256 };
pub const all_aeads = [_]AeadId{ .aes128gcm, .aes256gcm, .chacha20poly1305, .export_only };

/// The comptime KEM type behind a registered id.
pub fn KemOf(comptime id: KemId) type {
    return switch (id) {
        .dhkem_p256_hkdf_sha256 => dhkem.P256Kem,
        .dhkem_p384_hkdf_sha384 => dhkem.P384Kem,
        .dhkem_p521_hkdf_sha512 => dhkem.P521Kem,
        .dhkem_x25519_hkdf_sha256 => dhkem.X25519Kem,
        .dhkem_x448_hkdf_sha512 => dhkem.X448Kem,
        .ml_kem_512 => pq.MlKem512Kem,
        .ml_kem_768 => pq.MlKem768Kem,
        .ml_kem_1024 => pq.MlKem1024Kem,
        .mlkem768_p256 => pq.MlKem768P256Kem,
        .mlkem1024_p384 => pq.MlKem1024P384Kem,
        .mlkem768_x25519 => pq.MlKem768X25519Kem,
        _ => @compileError("hpke.agile: unknown KEM id"),
    };
}

/// The comptime KDF type behind a registered id.
pub fn KdfOf(comptime id: KdfId) type {
    return switch (id) {
        .hkdf_sha256 => kdf.HkdfSha256,
        .hkdf_sha384 => kdf.HkdfSha384,
        .hkdf_sha512 => kdf.HkdfSha512,
        .shake128 => kdf.Shake128,
        .shake256 => kdf.Shake256,
        .turboshake128 => kdf.TurboShake128,
        .turboshake256 => kdf.TurboShake256,
        _ => @compileError("hpke.agile: unknown KDF id"),
    };
}

/// The comptime AEAD type behind a registered id (`aesgcm`'s and
/// `chachapoly`'s, the module's recommended bindings).
pub fn AeadOf(comptime id: AeadId) type {
    return switch (id) {
        .aes128gcm => aesgcm.Aes128Gcm,
        .aes256gcm => aesgcm.Aes256Gcm,
        .chacha20poly1305 => chachapoly.ChaCha20Poly1305,
        .export_only => schedule.ExportOnly,
        _ => @compileError("hpke.agile: unknown AEAD id"),
    };
}

pub fn isPq(comptime K: type) bool {
    return @hasDecl(K, "Ephemeral");
}

fn maxOver(comptime field: []const u8) usize {
    var m: usize = 0;
    for (all_kems) |id| m = @max(m, @sizeOf(@field(KemOf(id), field)));
    return m;
}

/// The longest public key / `enc` / shared secret of any supported KEM
/// (MLKEM1024-P384's 1665-byte key and 1665-byte `enc`).
pub const max_public_key_len = maxOver("PublicKey");
pub const max_enc_len = maxOver("EncappedKey");
pub const max_nsecret = blk: {
    var m: usize = 0;
    for (all_kems) |id| m = @max(m, KemOf(id).Nsecret);
    break :blk m;
};
pub const max_nh = 64;

/// An id this module (or this `Agile` subset) does not implement.
pub const SuiteError = error{UnsupportedSuite};

/// Misuse a typed API would have caught at compile time: a key of another
/// KEM than the suite's (`KemMismatch`), an auth mode with a KEM that has no
/// AuthEncap or without the sender key it needs (`UnsupportedMode`), a
/// wrong-length `enc`/`ikmE`/private key/public key (`InvalidLength`),
/// `seal`/`open` on an export-only context (`ExportOnly`).
pub const UsageError = error{ KemMismatch, UnsupportedMode, InvalidLength, ExportOnly };

pub const KeyError = SuiteError || error{ InvalidLength, DeserializeError };
pub const SetupSError = schedule.SetupSError || UsageError || SuiteError;
pub const SetupRError = schedule.SetupRError || UsageError || SuiteError;
pub const SealError = schedule.SealError || UsageError;
pub const OpenError = schedule.OpenError || UsageError;
pub const SealOnceError = SetupSError || SealError;
pub const OpenOnceError = SetupRError || OpenError;

pub fn known(comptime E: type, comptime list: []const E, v: E) bool {
    inline for (list) |x| if (x == v) return true;
    return false;
}

/// A ciphersuite chosen at run time.
pub const Suite = struct {
    kem: KemId,
    kdf: KdfId,
    aead: AeadId,

    /// The suite of three registered ids (RFC 9180 Tables 2/3/5,
    /// draft-ietf-hpke-pq). An id this module does not implement is
    /// `error.UnsupportedSuite` (Go's `NewKEM`/`NewKDF`/`NewAEAD` error).
    /// Links no cryptographic code.
    pub fn init(kem_id: u16, kdf_id: u16, aead_id: u16) SuiteError!Suite {
        const s: Suite = .{ .kem = @fromBackingInt(@intCast(kem_id)), .kdf = @fromBackingInt(@intCast(kdf_id)), .aead = @fromBackingInt(@intCast(aead_id)) };
        if (!known(KemId, &all_kems, s.kem) or !known(KdfId, &all_kdfs, s.kdf) or !known(AeadId, &all_aeads, s.aead))
            return error.UnsupportedSuite;
        return s;
    }

    /// The §7.2.1 `suite_id` (`"HPKE" ‖ kem_id ‖ kdf_id ‖ aead_id`).
    pub fn id(self: Suite) [10]u8 {
        return suite.suiteId(@backingInt(self.kem), @backingInt(self.kdf), @backingInt(self.aead));
    }

    /// `Nenc`: the length of `enc` (0 for an id `init` refuses).
    pub fn encLength(self: Suite) usize {
        inline for (all_kems) |k| if (self.kem == k) return @sizeOf(KemOf(k).EncappedKey);
        return 0;
    }

    /// `Nt`: what `seal` adds to a plaintext (0 for export-only).
    pub fn tagLength(self: Suite) usize {
        inline for (all_aeads) |a| if (self.aead == a) return AeadOf(a).tag_length;
        return 0;
    }
};

/// A recipient's (or auth sender's) public key, KEM-tagged. Build it with
/// `publicKeyFromBytes` or `KeyPair.publicKey`.
pub const PublicKey = struct {
    kem: KemId,
    len: usize,
    bytes: [max_public_key_len]u8,

    pub fn slice(self: *const PublicKey) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn typed(self: *const PublicKey, comptime K: type) K.PublicKey {
        return self.bytes[0..K.Npk].*;
    }
};

/// A KEM key pair, one variant per KEM (the field name is the `KemId` tag
/// name). Holds the private key: wipe it
/// (`std.crypto.secureZero(u8, std.mem.asBytes(&kp))`) when done.
pub const KeyPair = union(enum) {
    dhkem_p256_hkdf_sha256: dhkem.P256Kem.KeyPair,
    dhkem_p384_hkdf_sha384: dhkem.P384Kem.KeyPair,
    dhkem_p521_hkdf_sha512: dhkem.P521Kem.KeyPair,
    dhkem_x25519_hkdf_sha256: dhkem.X25519Kem.KeyPair,
    dhkem_x448_hkdf_sha512: dhkem.X448Kem.KeyPair,
    ml_kem_512: pq.MlKem512Kem.KeyPair,
    ml_kem_768: pq.MlKem768Kem.KeyPair,
    ml_kem_1024: pq.MlKem1024Kem.KeyPair,
    mlkem768_p256: pq.MlKem768P256Kem.KeyPair,
    mlkem1024_p384: pq.MlKem1024P384Kem.KeyPair,
    mlkem768_x25519: pq.MlKem768X25519Kem.KeyPair,

    pub fn kemId(self: *const KeyPair) KemId {
        return switch (self.*) {
            inline else => |_, tag| @field(KemId, @tagName(tag)),
        };
    }

    /// The public half (Go `PrivateKey.PublicKey`).
    pub fn publicKey(self: *const KeyPair) PublicKey {
        switch (self.*) {
            inline else => |*k| {
                var out: PublicKey = .{ .kem = self.kemId(), .len = k.public_key.len, .bytes = undefined };
                @memcpy(out.bytes[0..k.public_key.len], &k.public_key);
                return out;
            },
        }
    }

    /// The serialized private key (Go `PrivateKey.Bytes`): the DHKEM scalar
    /// as stored, or the ML-KEM / hybrid seed. A view into `self`.
    pub fn secretBytes(self: *const KeyPair) []const u8 {
        return switch (self.*) {
            inline else => |*k| if (@hasField(@TypeOf(k.*), "seed")) &k.seed else &k.secret_key,
        };
    }
};

/// Which KEMs, KDFs and AEADs an `Agile` instance dispatches over.
pub const Options = struct {
    kems: []const KemId = &all_kems,
    kdfs: []const KdfId = &all_kdfs,
    aeads: []const AeadId = &all_aeads,
};

/// The runtime-agile API over the subset `opts`: only the listed KEMs, KDFs
/// and AEADs are compiled in, every other id is `error.UnsupportedSuite`.
pub const Agile = @import("agile_set.zig").Agile;

/// The per-message state: a comptime `Context` over the suite's AEAD (its
/// `exporter_secret` unused; the agile `Context` keeps its own, `Nh` wide).
pub const Msg = union(enum) {
    aes128gcm: schedule.Context(aesgcm.Aes128Gcm, 32),
    aes256gcm: schedule.Context(aesgcm.Aes256Gcm, 32),
    chacha20poly1305: schedule.Context(chachapoly.ChaCha20Poly1305, 32),
    export_only: void,
};

pub fn checkMode(comptime K: type, mode: Mode, have_auth_key: bool) UsageError!void {
    const auth = mode == .auth or mode == .auth_psk;
    if (auth != have_auth_key) return error.UnsupportedMode;
    if (auth and comptime isPq(K)) return error.UnsupportedMode;
}

pub const EphSource = union(enum) { io: std.Io, ikm: []const u8 };

// ── the full set: every KEM, KDF and AEAD of the module ──────────────────

const Full = Agile(.{});
pub const Context = Full.Context;
pub const Setup = Full.Setup;
pub const publicKeyFromBytes = Full.publicKeyFromBytes;
pub const generateKeyPair = Full.generateKeyPair;
pub const deriveKeyPair = Full.deriveKeyPair;
pub const keyPairFromSecret = Full.keyPairFromSecret;
pub const setupS = Full.setupS;
pub const setupSDeterministic = Full.setupSDeterministic;
pub const setupR = Full.setupR;
pub const sealBase = Full.sealBase;
pub const openBase = Full.openBase;
