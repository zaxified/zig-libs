// SPDX-License-Identifier: MIT
//! HPKE key schedule + encryption context (RFC 9180 §5): `KeySchedule`
//! (§5.1, mode/PSK/info -> `Context`), `Context.seal`/`.open`/
//! `.exportSecret` (§5.2/§5.3), §5.1's own `setupBaseS`/`setupBaseR` (+
//! `psk`/`auth`/`auth_psk` variants) which hand back the `Context` itself
//! for multi-message/export-only use, and §6.1's single-shot wrappers for
//! all four modes — `sealBase`/`sealPsk`/`sealAuth`/`sealAuthPsk` and their
//! `open*` mirrors, now thin compositions over the `setup*` functions. All
//! REAL (crypto-implementation pass done) —
//! KAT-validated against RFC 9180 Appendix A.1's published
//! key/base_nonce/exporter_secret, all 6 encryption tuples, and all 3
//! exported values, in every mode (A.1.1/A.1.2/A.1.3/A.1.4, plus the
//! P-256 suite's A.3.x; see `kat_rfc9180.zig`). The KDF is hard-wired to
//! HKDF-SHA256 (the only `KdfId` this module instantiates — `Nh` is kept
//! as an explicit parameter so widening to HKDF-SHA384/512 later is a
//! type-parameter change, not a resignature).

const std = @import("std");
const suite = @import("suite.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// RFC 9180 §5.2: the AEAD hit its sequence-number ceiling
/// (`2^(8*Nn) - 1`, though this implementation conservatively caps at
/// `maxInt(u64)` — see `Context.nextNonce`'s doc comment) — the connection
/// MUST be torn down and re-keyed, per spec, rather than reusing a nonce.
pub const SeqError = error{MessageLimitReached};

/// RFC 9180 §5.2 `Context.Seal`/`Open` errors: authentication failure on
/// `Open`, `SeqError` shared with the nonce-increment guard both
/// directions, and `InvalidLength` — the caller-supplied `out` buffer
/// isn't exactly `pt.len + Aead.tag_length` (`seal`) / `ct.len -
/// Aead.tag_length` (`open`). This used to be a `std.debug.assert`
/// (compiled out under `-Doptimize=ReleaseFast`/`ReleaseSmall`, where a
/// wrong-length caller buffer would fall straight through to
/// `Aead.encrypt`/`.decrypt` with a mismatched slice instead of failing
/// closed — RFC 9180 doesn't itself define a `SerializeError`-style code
/// for this, but every input-length precondition this module CAN check at
/// runtime should fail with a typed error in every build mode, not only in
/// Debug/ReleaseSafe; `zig-hpke`'s `SenderContext.seal`/
/// `RecipientContext.open` make the equivalent check unconditionally via
/// `error.InvalidEncoding`, never an assert).
pub const SealError = SeqError || error{InvalidLength};
pub const OpenError = SeqError || error{ DecryptionFailed, InvalidLength };

/// RFC 9180 §5.1: `KeySchedule`'s own precondition failures — a psk/
/// auth_psk call missing the PSK the mode requires, or vice versa (§5.1
/// Table 1's mode/PSK-requirement matrix), which this module DOES validate
/// up front (a pure "did the caller pass the right combination of optional
/// params" check, not a crypto judgment call) — plus §5.1.2's PSK-length
/// floor, the one strictness this module adds beyond the RFC's own
/// `VerifyPSKInputs` pseudocode.
pub const KeyScheduleError = error{
    /// `mode` is `.psk`/`.auth_psk` but `psk`/`psk_id` was empty, or
    /// `mode` is `.base`/`.auth` but a non-empty `psk`/`psk_id` was
    /// supplied (RFC 9180 §5.1 "VerifyPSKInputs").
    InconsistentPsk,
    /// A psk-bearing mode was given a PSK shorter than `Nh` (32 bytes for
    /// HKDF-SHA256, the only KDF this module instantiates). RFC 9180
    /// §5.1.2: "The PSK MUST have at least 32 bytes of entropy and SHOULD
    /// be of length Nh bytes or longer." A PSK shorter than 32 BYTES
    /// cannot carry 32 bytes of entropy, so a short PSK is a provable
    /// violation of that MUST, not merely of the SHOULD — this is the one
    /// part of §5.1.2 an implementation can actually check (entropy of a
    /// long-enough PSK is not observable from the bytes), and this module
    /// fails closed on it rather than deriving a key schedule from PSK
    /// material the RFC forbids. NOT part of RFC 9180's own
    /// `VerifyPSKInputs` pseudocode, which checks presence/consistency
    /// only; see SPEC.md's threat model for the deviation rationale.
    PskTooShort,
};

/// RFC 9180 §5.2: the AEAD nonce for sequence number `seq` — `base_nonce
/// XOR I2OSP(seq, Nn)` (the sequence number is right-aligned/big-endian
/// into the low-order bytes of an all-zero `Nn`-byte string, then XORed).
/// Pure arithmetic over caller-supplied bytes — KAT-validated against all
/// 6 of RFC 9180 A.1.1's published `(seq, nonce)` pairs.
pub fn computeNonce(comptime Nn: usize, base_nonce: [Nn]u8, seq: u64) [Nn]u8 {
    // RFC 9180's `seq` is conceptually an arbitrary-precision integer up
    // to 2^(8*Nn)-1 (Nn=12 for every AEAD this module targets, i.e. up to
    // 2^96-1) — this implementation narrows that to `u64` (2^64-1
    // messages), a conservative sub-limit of the spec's actual ceiling
    // documented in SPEC.md's threat model, not a spec deviation in the
    // covered range (u64's encoding is a strict subset of the full 96-bit
    // range, right-aligned identically).
    comptime std.debug.assert(Nn >= 8);
    var nonce = base_nonce;
    const seq_bytes = suite.i2osp(8, seq);
    const offset = Nn - 8;
    for (0..8) |i| nonce[offset + i] ^= seq_bytes[i];
    return nonce;
}

/// RFC 9180 §5.2: increment `seq`, failing with `error.MessageLimitReached`
/// instead of wrapping (the spec: "existing bounds should already prevent
/// callers from safely encoding the number of encryption operations that
/// this would require"). REAL — the overflow-guard arithmetic itself, no
/// AEAD/HKDF involvement.
pub fn incrementSeq(seq: *u64) SeqError!void {
    if (seq.* == std.math.maxInt(u64)) return error.MessageLimitReached;
    seq.* += 1;
}

/// RFC 9180 §5.1: an HPKE encryption context, parameterized on the AEAD
/// (`Aead` — `std.crypto.aead.aes_gcm.Aes128Gcm`/`Aes256Gcm` or
/// `std.crypto.aead.chacha_poly.ChaCha20Poly1305`) and the KDF's digest
/// width `Nh` (`std.crypto.kdf.hkdf.Hkdf(Hmac).prk_length` — 32 for every
/// suite this module targets, HKDF-SHA256).
///
/// Constructed by `keySchedule` below (or populate the fields directly if
/// a higher-level protocol transports them itself).
pub fn Context(comptime Aead: type, comptime Nh: usize) type {
    return struct {
        const Self = @This();
        pub const Nk = Aead.key_length;
        pub const Nn = Aead.nonce_length;

        key: [Nk]u8,
        base_nonce: [Nn]u8,
        seq: u64 = 0,
        exporter_secret: [Nh]u8,

        /// RFC 9180 §5.2 `Context.Seal(aad, pt)`: encrypt-then-derive-nonce
        /// -> `Aead.encrypt(ct_out, tag_out, pt, aad, computeNonce(Nn,
        /// self.base_nonce, self.seq), self.key)`, write the tag after the
        /// ciphertext (`out.len == pt.len + Aead.tag_length`), THEN
        /// `incrementSeq(&self.seq)` — the increment must happen only
        /// after a successful encrypt, and BEFORE returning, never
        /// skipped on the success path (an attacker who could force a
        /// nonce reuse breaks AES-GCM/ChaCha20-Poly1305 confidentiality
        /// outright — see SPEC.md's threat model).
        pub fn seal(self: *Self, aad: []const u8, pt: []const u8, out: []u8) SealError!void {
            // A wrong-length `out` is a caller/API-contract bug, not
            // attacker-controlled input — still a real runtime check (not
            // `std.debug.assert`, which ReleaseFast/ReleaseSmall compile
            // out) so a mismatched buffer fails closed with a typed error
            // in every build mode instead of `Aead.encrypt` below slicing
            // `out` on a wrong length.
            if (out.len != pt.len + Aead.tag_length) return error.InvalidLength;
            // Fail closed BEFORE producing any ciphertext: if `seq` could
            // not be advanced past this message, returning a ciphertext
            // alongside the error would leave a context whose next `seal`
            // reuses the same nonce — the exact break the threat model
            // forbids. (This makes seq == maxInt(u64) itself unusable, an
            // even more conservative sub-limit than incrementSeq alone.)
            if (self.seq == std.math.maxInt(u64)) return error.MessageLimitReached;
            const nonce = computeNonce(Nn, self.base_nonce, self.seq);
            Aead.encrypt(out[0..pt.len], out[pt.len..][0..Aead.tag_length], pt, aad, nonce, self.key);
            incrementSeq(&self.seq) catch unreachable; // guarded above
        }

        /// RFC 9180 §5.2 `Context.Open(aad, ct)` — the mirror: derive the
        /// SAME `computeNonce(Nn, self.base_nonce, self.seq)` (the
        /// receiver's `seq` must track the sender's, e.g. by processing
        /// messages in order — out-of-order/skipped sequence numbers are
        /// an application-level policy this module does not itself
        /// enforce beyond the raw counter), `Aead.decrypt(...)` mapping any
        /// authentication failure to `error.DecryptionFailed` (never a
        /// panic on attacker-controlled ciphertext), THEN `incrementSeq`
        /// only on a successful open (a rejected open must NOT advance
        /// `seq`, or a genuine subsequent message at that sequence number
        /// would be dropped).
        pub fn open(self: *Self, aad: []const u8, ct: []const u8, out: []u8) OpenError!void {
            // A ciphertext shorter than the tag is malformed
            // attacker-controlled input, never a panic (the slicing below
            // would otherwise assert) — treat it as an auth failure.
            if (ct.len < Aead.tag_length) return error.DecryptionFailed;
            // Caller/API-contract length check, real (not
            // `std.debug.assert`) for the same reason as `seal`'s — see
            // that function's comment.
            if (out.len != ct.len - Aead.tag_length) return error.InvalidLength;
            // Mirror of seal's fail-closed pre-check (see seal).
            if (self.seq == std.math.maxInt(u64)) return error.MessageLimitReached;
            const nonce = computeNonce(Nn, self.base_nonce, self.seq);
            const tag = ct[ct.len - Aead.tag_length ..][0..Aead.tag_length].*;
            Aead.decrypt(out, ct[0 .. ct.len - Aead.tag_length], tag, aad, nonce, self.key) catch
                return error.DecryptionFailed;
            // Only after a SUCCESSFUL open — a rejected ciphertext must
            // not advance `seq` (see this function's doc comment).
            incrementSeq(&self.seq) catch unreachable; // guarded above
        }

        /// RFC 9180 §5.3 `Context.Export(exporter_context, L)` =
        /// `LabeledExpand(suite_id, exporter_secret, "sec",
        /// exporter_context, L)` — the ONE `Context` operation that needs
        /// no sequence number / nonce at all (an exporter secret may be
        /// pulled from many times, unlike `seal`/`open`'s single-use-per-
        /// seq nonces).
        pub fn exportSecret(self: *const Self, suite_id: []const u8, exporter_context: []const u8, out: []u8) suite.LabeledExpandError!void {
            comptime std.debug.assert(Nh == HkdfSha256.prk_length); // KDF hard-wired to HKDF-SHA256 module-wide
            return suite.labeledExpand(HkdfSha256, suite_id, self.exporter_secret, "sec", exporter_context, out);
        }
    };
}

/// RFC 9180 §5.1 `KeySchedule(mode, shared_secret, info, psk, psk_id)` —
/// the composition step every other helper in this module feeds:
/// `suite.labeledExtract`/`suite.labeledExpand` supply every HKDF call.
/// KAT: reproduces the published `key`/`base_nonce`/`exporter_secret`
/// end-to-end from `shared_secret` for all four modes — A.1.1 (base),
/// A.1.2 (psk), A.1.3 (auth), A.1.4 (auth_psk), and the same three
/// non-base modes over the P-256 suite (A.3.2/A.3.3/A.3.4). See
/// `kat_rfc9180.zig`.
///
/// Recipe (RFC 9180 §5.1, `suite_id = suite.suiteId(kem_id, kdf_id,
/// aead_id)` — the OUTER suite id, not the KEM's):
/// ```text
/// VerifyPSKInputs(mode, psk, psk_id)   // KeyScheduleError.InconsistentPsk on a mismatch, see that error's doc comment
/// // plus §5.1.2's PSK floor: a psk shorter than Nh -> KeyScheduleError.PskTooShort (NOT in the RFC's VerifyPSKInputs pseudocode; see that error's doc comment)
/// psk_id_hash = LabeledExtract(suite_id, "", "psk_id_hash", psk_id)
/// info_hash   = LabeledExtract(suite_id, "", "info_hash", info)
/// key_schedule_context = concat(I2OSP(mode, 1), psk_id_hash, info_hash)
/// secret = LabeledExtract(suite_id, shared_secret, "secret", psk)
/// key           = LabeledExpand(suite_id, secret, "key", key_schedule_context, Nk)          // skipped entirely if aead_id == export_only (0xFFFF)
/// base_nonce    = LabeledExpand(suite_id, secret, "base_nonce", key_schedule_context, Nn)    // skipped entirely if aead_id == export_only
/// exporter_secret = LabeledExpand(suite_id, secret, "exp", key_schedule_context, Nh)
/// return Context{ key, base_nonce, seq: 0, exporter_secret }
/// ```
/// `suite.zig`'s own test (`labeledExtract/labeledExpand: RFC 9180 A.1.1
/// key_schedule_context + secret, byte-exact`) exercises this EXACT
/// sequence against the A.1.1 vector by hand — this function is that
/// test's body wrapped in a `Context` constructor.
pub fn keySchedule(
    comptime Aead: type,
    comptime Nh: usize,
    mode: suite.Mode,
    suite_id: []const u8,
    shared_secret: []const u8,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
) (KeyScheduleError || suite.LabeledExpandError)!Context(Aead, Nh) {
    comptime std.debug.assert(Nh == HkdfSha256.prk_length); // KDF hard-wired to HKDF-SHA256 module-wide

    // VerifyPSKInputs (RFC 9180 §5.1): psk and psk_id must be present or
    // absent TOGETHER, and present iff the mode calls for a PSK.
    const got_psk = psk.len != 0;
    if (got_psk != (psk_id.len != 0)) return error.InconsistentPsk;
    const mode_needs_psk = mode == .psk or mode == .auth_psk;
    if (got_psk != mode_needs_psk) return error.InconsistentPsk;
    // §5.1.2's PSK-strength floor, checked AFTER the consistency rules so a
    // caller who got the mode/PSK combination wrong still sees
    // `InconsistentPsk` (the RFC's own diagnosis) rather than a length
    // complaint about a PSK that shouldn't have been supplied at all.
    if (got_psk and psk.len < Nh) return error.PskTooShort;

    const psk_id_hash = suite.labeledExtract(HkdfSha256, suite_id, "", "psk_id_hash", psk_id);
    const info_hash = suite.labeledExtract(HkdfSha256, suite_id, "", "info_hash", info);

    // key_schedule_context = I2OSP(mode, 1) || psk_id_hash || info_hash
    var ksc: [1 + 2 * Nh]u8 = undefined;
    ksc[0] = @intFromEnum(mode);
    ksc[1 .. 1 + Nh].* = psk_id_hash;
    ksc[1 + Nh ..].* = info_hash;

    const secret = suite.labeledExtract(HkdfSha256, suite_id, shared_secret, "secret", psk);

    var ctx = Context(Aead, Nh){
        .key = undefined,
        .base_nonce = undefined,
        .seq = 0,
        .exporter_secret = undefined,
    };
    try suite.labeledExpand(HkdfSha256, suite_id, secret, "key", &ksc, &ctx.key);
    try suite.labeledExpand(HkdfSha256, suite_id, secret, "base_nonce", &ksc, &ctx.base_nonce);
    try suite.labeledExpand(HkdfSha256, suite_id, secret, "exp", &ksc, &ctx.exporter_secret);
    return ctx;
}

// ── single-shot base-mode convenience wrappers (RFC 9180 §6.1) ──────────

/// The registered `AeadId` for a `std.crypto` AEAD type — needed by the
/// single-shot wrappers below to assemble the outer `suite_id` (§7.2.1)
/// from their comptime type parameters alone. A compile error (not a
/// runtime fallback) for an AEAD RFC 9180 doesn't register.
fn aeadIdOf(comptime Aead: type) u16 {
    if (Aead == std.crypto.aead.aes_gcm.Aes128Gcm) return @intFromEnum(suite.AeadId.aes128gcm);
    if (Aead == std.crypto.aead.aes_gcm.Aes256Gcm) return @intFromEnum(suite.AeadId.aes256gcm);
    if (Aead == std.crypto.aead.chacha_poly.ChaCha20Poly1305) return @intFromEnum(suite.AeadId.chacha20poly1305);
    @compileError("hpke: no RFC 9180 aead_id registered for " ++ @typeName(Aead));
}

/// The outer HPKE `suite_id` (§7.2.1) for a `(Kem, Aead)` pair — kdf_id is
/// hard-wired to HKDF-SHA256, the only KDF this module instantiates.
fn suiteIdOf(comptime Kem: type, comptime Aead: type) [10]u8 {
    return suite.suiteId(Kem.kem_id, @intFromEnum(suite.KdfId.hkdf_sha256), aeadIdOf(Aead));
}

/// `sealBase`/`sealBaseDeterministic`'s result: the `enc` the sender must
/// transmit alongside the ciphertext (a named type so both entry points
/// share one return type — Zig's anonymous `struct { ... }` returns are
/// distinct types per declaration site).
pub fn Sealed(comptime Kem: type) type {
    return struct { enc: Kem.EncappedKey };
}

// ── setup: obtain the multi-message Context itself (RFC 9180 §5.1 ──────
// `SetupBaseS`/`SetupBaseR` + the psk/auth/auth_psk variants) ───────────
//
// The single-shot `seal*`/`open*` wrappers above run `KeySchedule` and then
// immediately consume the resulting `Context` for exactly ONE `Seal`/`Open`
// — the RFC's §6.1 convenience layer, for the (extremely common) one-message
// case. §5.1 itself is one layer lower: `SetupBaseS(pkR, info)` etc. return
// the encapsulation and the `Context`, full stop — no assumption that the
// caller wants to seal anything at all. A caller that only ever wants
// `Context.Export` (RFC 9420 MLS's external-init/external-commit, §8.3/
// §12.4 — derive `init_secret` from an HPKE exchange, never `Seal`/`Open`
// a message through it) needs exactly this layer, not §6.1's.
//
// `setup*S`/`setup*R` are additive: they call the exact same
// `Kem.encap*`/`Kem.decap*`/`Kem.authEncap*`/`Kem.authDecap*` + `keySchedule`
// steps the single-shot wrappers already call (see `setupEncapped`/
// `setupDecapped` below, which `sealEncapped`/`openDecapped` now compose
// over too) — no new crypto, just a stopping point one step earlier that
// hands back the `Context` instead of consuming it.

/// `setup*S`/`setup*SDeterministic`'s result: the `enc` the sender must
/// transmit, paired with the `Context` the caller now owns for as many
/// `seal`/`open`/`exportSecret` calls as its protocol needs — unlike
/// `Sealed`, which is `sealBase`'s single-shot return with no `Context`
/// exposed at all.
pub fn Setup(comptime Kem: type, comptime Aead: type, comptime Nh: usize) type {
    return struct { enc: Kem.EncappedKey, context: Context(Aead, Nh) };
}

/// The post-KEM half of every `setup*S` entry point below: `KeySchedule(mode,
/// shared_secret, info, psk, psk_id)`, packaged with the `enc` the sender
/// must transmit. `sealEncapped` (the single-shot `Seal*` wrappers' shared
/// body, further down) is now a thin wrapper over this plus one
/// `Context.seal` — see that function's doc comment.
fn setupEncapped(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    encapped: Kem.Encapped,
    mode: suite.Mode,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
) !Setup(Kem, Aead, Nh) {
    const suite_id = comptime suiteIdOf(Kem, Aead);
    const context = try keySchedule(Aead, Nh, mode, &suite_id, &encapped.shared_secret, info, psk, psk_id);
    return .{ .enc = encapped.enc, .context = context };
}

/// The post-KEM half of every `setup*R` entry point below — the mirror of
/// `setupEncapped`. `openDecapped` is now a thin wrapper over this plus one
/// `Context.open`.
fn setupDecapped(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    shared_secret: [Kem.Nsecret]u8,
    mode: suite.Mode,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
) !Context(Aead, Nh) {
    const suite_id = comptime suiteIdOf(Kem, Aead);
    return keySchedule(Aead, Nh, mode, &suite_id, &shared_secret, info, psk, psk_id);
}

/// RFC 9180 §5.1 `SetupBaseS(pkR, info)`: `Encap(pkR)` then
/// `KeySchedule(mode_base, shared_secret, info, "", "")`, returning `enc`
/// alongside the `Context` itself (contrast `sealBase`, which consumes the
/// `Context` for exactly one `Seal` and never exposes it).
pub fn setupBaseS(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    io: std.Io,
    info: []const u8,
) !Setup(Kem, Aead, Nh) {
    return setupBaseSDeterministic(Kem, Aead, Nh, pkR, Kem.generateKeyPair(io), info);
}

/// `setupBaseS` with the ephemeral keypair injected instead of drawn from
/// `io` — the KAT seam, same pattern as `sealBaseDeterministic`. Real
/// callers want `setupBaseS`.
pub fn setupBaseSDeterministic(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    eph: Kem.KeyPair,
    info: []const u8,
) !Setup(Kem, Aead, Nh) {
    return setupEncapped(Kem, Aead, Nh, try Kem.encapDeterministic(pkR, eph), .base, info, "", "");
}

/// RFC 9180 §5.1 `SetupBaseR(enc, skR, info)` — the receiver mirror of
/// `setupBaseS`: `Decap(enc, skR)` then the same `KeySchedule` call,
/// returning the `Context` alone (the receiver already has `enc` — nothing
/// to echo back).
pub fn setupBaseR(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    enc: Kem.EncappedKey,
    skR: Kem.KeyPair,
    info: []const u8,
) !Context(Aead, Nh) {
    return setupDecapped(Kem, Aead, Nh, try Kem.decap(enc, skR), .base, info, "", "");
}

/// RFC 9180 §5.1 `SetupPSKS(pkR, info, psk, psk_id)` — `setupBaseS`'s
/// psk-mode sibling, parameter order matching `sealPsk` (minus `aad`/`pt`/
/// `out`). `psk` MUST be at least `Nh` bytes (§5.1.2); `keySchedule`
/// enforces that, `error.PskTooShort`.
pub fn setupPskS(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    io: std.Io,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
) !Setup(Kem, Aead, Nh) {
    return setupPskSDeterministic(Kem, Aead, Nh, pkR, Kem.generateKeyPair(io), info, psk, psk_id);
}

/// `setupPskS` with the ephemeral keypair injected — the KAT seam.
pub fn setupPskSDeterministic(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    eph: Kem.KeyPair,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
) !Setup(Kem, Aead, Nh) {
    return setupEncapped(Kem, Aead, Nh, try Kem.encapDeterministic(pkR, eph), .psk, info, psk, psk_id);
}

/// RFC 9180 §5.1 `SetupPSKR(enc, skR, info, psk, psk_id)` — the receiver
/// mirror of `setupPskS`.
pub fn setupPskR(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    enc: Kem.EncappedKey,
    skR: Kem.KeyPair,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
) !Context(Aead, Nh) {
    return setupDecapped(Kem, Aead, Nh, try Kem.decap(enc, skR), .psk, info, psk, psk_id);
}

/// RFC 9180 §5.1 `SetupAuthS(pkR, info, skS)` — `setupBaseS`'s auth-mode
/// sibling: `AuthEncap(pkR, skS)` then `KeySchedule(mode_auth, ...)`.
/// Parameter order matches `sealAuth` (minus `aad`/`pt`/`out`).
pub fn setupAuthS(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    skS: Kem.KeyPair,
    io: std.Io,
    info: []const u8,
) !Setup(Kem, Aead, Nh) {
    return setupAuthSDeterministic(Kem, Aead, Nh, pkR, skS, Kem.generateKeyPair(io), info);
}

/// `setupAuthS` with the ephemeral keypair injected — the KAT seam. `eph`
/// and the sender's static keypair `skS` are DIFFERENT keys, exactly as in
/// `sealAuthDeterministic`.
pub fn setupAuthSDeterministic(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    skS: Kem.KeyPair,
    eph: Kem.KeyPair,
    info: []const u8,
) !Setup(Kem, Aead, Nh) {
    return setupEncapped(Kem, Aead, Nh, try Kem.authEncapDeterministic(pkR, skS, eph), .auth, info, "", "");
}

/// RFC 9180 §5.1 `SetupAuthR(enc, skR, info, pkS)` — the receiver mirror of
/// `setupAuthS`; `pkS` is REQUIRED, exactly as in `openAuth`.
pub fn setupAuthR(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    enc: Kem.EncappedKey,
    skR: Kem.KeyPair,
    pkS: Kem.PublicKey,
    info: []const u8,
) !Context(Aead, Nh) {
    return setupDecapped(Kem, Aead, Nh, try Kem.authDecap(enc, skR, pkS), .auth, info, "", "");
}

/// RFC 9180 §5.1 `SetupAuthPSKS(pkR, info, psk, psk_id, skS)` — both
/// authenticators at once. Parameter order matches `sealAuthPsk` (minus
/// `aad`/`pt`/`out`).
pub fn setupAuthPskS(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    skS: Kem.KeyPair,
    io: std.Io,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
) !Setup(Kem, Aead, Nh) {
    return setupAuthPskSDeterministic(Kem, Aead, Nh, pkR, skS, Kem.generateKeyPair(io), info, psk, psk_id);
}

/// `setupAuthPskS` with the ephemeral keypair injected — the KAT seam.
pub fn setupAuthPskSDeterministic(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    skS: Kem.KeyPair,
    eph: Kem.KeyPair,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
) !Setup(Kem, Aead, Nh) {
    return setupEncapped(Kem, Aead, Nh, try Kem.authEncapDeterministic(pkR, skS, eph), .auth_psk, info, psk, psk_id);
}

/// RFC 9180 §5.1 `SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS)` — the
/// receiver mirror of `setupAuthPskS`.
pub fn setupAuthPskR(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    enc: Kem.EncappedKey,
    skR: Kem.KeyPair,
    pkS: Kem.PublicKey,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
) !Context(Aead, Nh) {
    return setupDecapped(Kem, Aead, Nh, try Kem.authDecap(enc, skR, pkS), .auth_psk, info, psk, psk_id);
}

/// RFC 9180 §6.1 `SealBase(pkR, info, aad, pt)`: `Encap(pkR)` (a
/// `dhkem.*Kem.encap` call) then `KeySchedule(mode_base, shared_secret,
/// info, "", "")` then one `Context.Seal(aad, pt)` — a single-shot helper
/// for the (extremely common) case of exactly one sealed message per
/// encryption context.
pub fn sealBase(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    io: std.Io,
    info: []const u8,
    aad: []const u8,
    pt: []const u8,
    out: []u8,
) !Sealed(Kem) {
    return sealBaseDeterministic(Kem, Aead, Nh, pkR, Kem.generateKeyPair(io), info, aad, pt, out);
}

/// `sealBase` with the ephemeral keypair injected instead of drawn from
/// `io` — the KAT seam (RFC 9180 Appendix A fixes `skEm`/`pkEm`), same
/// pattern as `dhkem`'s `encapDeterministic`. Real callers want
/// `sealBase`; reusing an ephemeral key across calls voids HPKE's
/// security argument.
pub fn sealBaseDeterministic(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    eph: Kem.KeyPair,
    info: []const u8,
    aad: []const u8,
    pt: []const u8,
    out: []u8,
) !Sealed(Kem) {
    return sealEncapped(Kem, Aead, Nh, try Kem.encapDeterministic(pkR, eph), .base, info, "", "", aad, pt, out);
}

/// RFC 9180 §6.1 `OpenBase(enc, skR, info, aad, ct)`: the receiver mirror
/// of `sealBase` — `Decap(enc, skR)` then the same `KeySchedule` call then
/// one `Context.Open`.
pub fn openBase(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    enc: Kem.EncappedKey,
    skR: Kem.KeyPair,
    info: []const u8,
    aad: []const u8,
    ct: []const u8,
    out: []u8,
) !void {
    return openDecapped(Kem, Aead, Nh, try Kem.decap(enc, skR), .base, info, "", "", aad, ct, out);
}

// ── single-shot psk / auth / auth_psk wrappers (RFC 9180 §6.1) ──────────
//
// §6.1 defines SealPSK/OpenPSK, SealAuth/OpenAuth and SealAuthPSK/
// OpenAuthPSK as exactly SealBase/OpenBase with (a) the mode byte, (b) the
// psk/psk_id pair, and (c) the KEM's authenticated fold swapped in. Every
// one of them is therefore the SAME three-step composition, and they share
// the `sealEncapped`/`openDecapped` bodies below rather than each carrying
// its own copy of the key-schedule + seal lines — a per-mode copy is
// precisely where a `mode` argument or a `psk` argument silently goes
// missing, and (unlike a KAT mismatch) a sender and recipient making the
// same omission still round-trip perfectly.
//
// Parameter order mirrors `sealBase`/`openBase` exactly, with each extra
// input placed next to its own kind: the sender's static keypair `skS` /
// public key `pkS` next to the other KEM key (`pkR`/`skR`), and
// `psk`/`psk_id` next to the other key-schedule input (`info`). `aad`, `pt`
// / `ct` and `out` stay last, unchanged.

/// The post-KEM half of every single-shot `Seal*`: `setupEncapped` (§5.1
/// `KeySchedule`) then exactly ONE `Context.Seal(aad, pt)` — literally
/// `setup*S` immediately followed by one seal, discarding the `Context`
/// afterward. `mode`'s consistency with `psk`/`psk_id` is not re-checked
/// here — `keySchedule` (reached through `setupEncapped`) owns RFC 9180
/// §5.1's `VerifyPSKInputs` (plus §5.1.2's PSK floor) and rejects a wrong
/// combination with `KeyScheduleError`, so a duplicate check in each
/// wrapper would only be a second place to get the rule wrong.
fn sealEncapped(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    encapped: Kem.Encapped,
    mode: suite.Mode,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
    aad: []const u8,
    pt: []const u8,
    out: []u8,
) !Sealed(Kem) {
    var setup = try setupEncapped(Kem, Aead, Nh, encapped, mode, info, psk, psk_id);
    try setup.context.seal(aad, pt, out);
    return .{ .enc = setup.enc };
}

/// The post-KEM half of every single-shot `Open*` — the mirror of
/// `sealEncapped`: `setupDecapped` then exactly ONE `Context.Open`.
fn openDecapped(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    shared_secret: [Kem.Nsecret]u8,
    mode: suite.Mode,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
    aad: []const u8,
    ct: []const u8,
    out: []u8,
) !void {
    var context = try setupDecapped(Kem, Aead, Nh, shared_secret, mode, info, psk, psk_id);
    try context.open(aad, ct, out);
}

/// RFC 9180 §6.1 `SealPSK(pkR, info, aad, pt, psk, psk_id)`: `Encap(pkR)`
/// (the same unauthenticated KEM call `sealBase` makes) then
/// `KeySchedule(mode_psk, shared_secret, info, psk, psk_id)` then one
/// `Context.Seal`. The recipient is assured the sender held `psk`; the
/// sender is assured of nothing about the recipient beyond `pkR`, exactly
/// as in base mode. `psk` MUST be at least `Nh` bytes (RFC 9180 §5.1.2) —
/// `keySchedule` enforces that, `error.PskTooShort`.
/// KAT: reproduces RFC 9180 A.1.2's `enc` + first ciphertext.
pub fn sealPsk(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    io: std.Io,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
    aad: []const u8,
    pt: []const u8,
    out: []u8,
) !Sealed(Kem) {
    return sealPskDeterministic(Kem, Aead, Nh, pkR, Kem.generateKeyPair(io), info, psk, psk_id, aad, pt, out);
}

/// `sealPsk` with the ephemeral keypair injected instead of drawn from
/// `io` — the KAT seam, exactly as `sealBaseDeterministic` is to
/// `sealBase`. Real callers want `sealPsk`.
pub fn sealPskDeterministic(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    eph: Kem.KeyPair,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
    aad: []const u8,
    pt: []const u8,
    out: []u8,
) !Sealed(Kem) {
    return sealEncapped(Kem, Aead, Nh, try Kem.encapDeterministic(pkR, eph), .psk, info, psk, psk_id, aad, pt, out);
}

/// RFC 9180 §6.1 `OpenPSK(enc, skR, info, aad, ct, psk, psk_id)` — the
/// receiver mirror of `sealPsk`. A recipient holding a DIFFERENT `psk` (or
/// the same `psk` under a different `psk_id`) derives a different key
/// schedule and the AEAD open fails with `error.DecryptionFailed`; that is
/// the entire authentication the mode provides.
pub fn openPsk(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    enc: Kem.EncappedKey,
    skR: Kem.KeyPair,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
    aad: []const u8,
    ct: []const u8,
    out: []u8,
) !void {
    return openDecapped(Kem, Aead, Nh, try Kem.decap(enc, skR), .psk, info, psk, psk_id, aad, ct, out);
}

/// RFC 9180 §6.1 `SealAuth(pkR, info, aad, pt, skS)`: `AuthEncap(pkR, skS)`
/// — the KEM fold that binds the SENDER's static keypair into the shared
/// secret (`dh || dh2`, see `dhkem.zig`) — then `KeySchedule(mode_auth,
/// shared_secret, info, "", "")` then one `Context.Seal`. `skS` is a
/// long-term keypair the recipient must already know the public half of;
/// reusing it is the point of the mode (unlike the per-call ephemeral).
/// KAT: reproduces RFC 9180 A.1.3's `enc` + first ciphertext.
pub fn sealAuth(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    skS: Kem.KeyPair,
    io: std.Io,
    info: []const u8,
    aad: []const u8,
    pt: []const u8,
    out: []u8,
) !Sealed(Kem) {
    return sealAuthDeterministic(Kem, Aead, Nh, pkR, skS, Kem.generateKeyPair(io), info, aad, pt, out);
}

/// `sealAuth` with the ephemeral keypair injected — the KAT seam. Note the
/// ephemeral (`eph`) and the sender's static keypair (`skS`) are DIFFERENT
/// keys serving different purposes; passing the static key as the ephemeral
/// would destroy HPKE's per-message key freshness.
pub fn sealAuthDeterministic(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    skS: Kem.KeyPair,
    eph: Kem.KeyPair,
    info: []const u8,
    aad: []const u8,
    pt: []const u8,
    out: []u8,
) !Sealed(Kem) {
    return sealEncapped(Kem, Aead, Nh, try Kem.authEncapDeterministic(pkR, skS, eph), .auth, info, "", "", aad, pt, out);
}

/// RFC 9180 §6.1 `OpenAuth(enc, skR, info, aad, ct, pkS)` — the receiver
/// mirror of `sealAuth`. `pkS` is REQUIRED (no "authenticate against
/// whoever sent it" path): `AuthDecap` with the wrong `pkS` yields a
/// different shared secret and the open fails, which IS the sender
/// authentication — see SPEC.md's threat model on sender-key confusion.
pub fn openAuth(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    enc: Kem.EncappedKey,
    skR: Kem.KeyPair,
    pkS: Kem.PublicKey,
    info: []const u8,
    aad: []const u8,
    ct: []const u8,
    out: []u8,
) !void {
    return openDecapped(Kem, Aead, Nh, try Kem.authDecap(enc, skR, pkS), .auth, info, "", "", aad, ct, out);
}

/// RFC 9180 §6.1 `SealAuthPSK(pkR, info, aad, pt, psk, psk_id, skS)`: both
/// authenticators at once — `AuthEncap(pkR, skS)` AND a psk-bearing
/// `KeySchedule(mode_auth_psk, ...)`. The recipient is assured the sender
/// held BOTH the static private key matching `pkS` and the PSK.
/// KAT: reproduces RFC 9180 A.1.4's `enc` + first ciphertext.
pub fn sealAuthPsk(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    skS: Kem.KeyPair,
    io: std.Io,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
    aad: []const u8,
    pt: []const u8,
    out: []u8,
) !Sealed(Kem) {
    return sealAuthPskDeterministic(Kem, Aead, Nh, pkR, skS, Kem.generateKeyPair(io), info, psk, psk_id, aad, pt, out);
}

/// `sealAuthPsk` with the ephemeral keypair injected — the KAT seam.
pub fn sealAuthPskDeterministic(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    pkR: Kem.PublicKey,
    skS: Kem.KeyPair,
    eph: Kem.KeyPair,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
    aad: []const u8,
    pt: []const u8,
    out: []u8,
) !Sealed(Kem) {
    return sealEncapped(Kem, Aead, Nh, try Kem.authEncapDeterministic(pkR, skS, eph), .auth_psk, info, psk, psk_id, aad, pt, out);
}

/// RFC 9180 §6.1 `OpenAuthPSK(enc, skR, info, aad, ct, psk, psk_id, pkS)` —
/// the receiver mirror of `sealAuthPsk`; a wrong `pkS` OR a wrong
/// `psk`/`psk_id` fails the open.
pub fn openAuthPsk(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    enc: Kem.EncappedKey,
    skR: Kem.KeyPair,
    pkS: Kem.PublicKey,
    info: []const u8,
    psk: []const u8,
    psk_id: []const u8,
    aad: []const u8,
    ct: []const u8,
    out: []u8,
) !void {
    return openDecapped(Kem, Aead, Nh, try Kem.authDecap(enc, skR, pkS), .auth_psk, info, psk, psk_id, aad, ct, out);
}

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "computeNonce: base_nonce XOR I2OSP(seq, Nn) — RFC 9180 A.1.1 seq 0/1/2/255/256" {
    const base_nonce = [_]u8{ 0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x01, 0x1c, 0xff, 0x4b, 0x7d };
    try testing.expectEqualSlices(u8, &base_nonce, &computeNonce(12, base_nonce, 0));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x01, 0x1c, 0xff, 0x4b, 0x7c }, &computeNonce(12, base_nonce, 1));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x01, 0x1c, 0xff, 0x4b, 0x7f }, &computeNonce(12, base_nonce, 2));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x01, 0x1c, 0xff, 0x4b, 0x82 }, &computeNonce(12, base_nonce, 255));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x01, 0x1c, 0xff, 0x4a, 0x7d }, &computeNonce(12, base_nonce, 256));
}

test "incrementSeq: overflow guard fails closed at maxInt(u64), never wraps" {
    var seq: u64 = std.math.maxInt(u64) - 1;
    try incrementSeq(&seq);
    try testing.expectEqual(std.math.maxInt(u64), seq);
    try testing.expectError(error.MessageLimitReached, incrementSeq(&seq));
    try testing.expectEqual(std.math.maxInt(u64), seq); // unchanged on rejection
}

/// A PSK long enough to clear RFC 9180 §5.1.2's `Nh`-byte floor — test-only
/// filler, NOT key material anything outside this file may reuse.
const test_psk = [_]u8{0xab} ** 32;

test "keySchedule: VerifyPSKInputs rejects every inconsistent mode/psk combination" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ss = [_]u8{0x42} ** 32;
    // base mode with a PSK supplied.
    try testing.expectError(error.InconsistentPsk, keySchedule(Aes128Gcm, 32, .base, &suite_id, &ss, "", &test_psk, "some id"));
    // psk mode with no PSK.
    try testing.expectError(error.InconsistentPsk, keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", "", ""));
    // psk without psk_id (and vice versa).
    try testing.expectError(error.InconsistentPsk, keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", &test_psk, ""));
    try testing.expectError(error.InconsistentPsk, keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", "", "some id"));
    // A too-short PSK in an otherwise-CONSISTENT combination is still
    // reported as an inconsistency, not a length problem — the mode/PSK
    // shape rules are checked first (see keySchedule).
    try testing.expectError(error.InconsistentPsk, keySchedule(Aes128Gcm, 32, .auth, &suite_id, &ss, "", "short", "some id"));
    // Consistent combinations construct fine.
    _ = try keySchedule(Aes128Gcm, 32, .base, &suite_id, &ss, "", "", "");
    _ = try keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", &test_psk, "some id");
    _ = try keySchedule(Aes128Gcm, 32, .auth, &suite_id, &ss, "", "", "");
    _ = try keySchedule(Aes128Gcm, 32, .auth_psk, &suite_id, &ss, "", &test_psk, "some id");
}

test "keySchedule: RFC 9180 §5.1.2 PSK floor — a psk shorter than Nh fails closed with error.PskTooShort" {
    // "The PSK MUST have at least 32 bytes of entropy" (§5.1.2): a PSK
    // shorter than 32 BYTES cannot satisfy that, whatever its content, so
    // this module rejects it rather than deriving a key schedule from it.
    // Not part of the RFC's VerifyPSKInputs pseudocode — see
    // KeyScheduleError.PskTooShort's doc comment and SPEC.md.
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ss = [_]u8{0x42} ** 32;
    for ([_]usize{ 1, 8, 16, 31 }) |n| {
        const short = ([_]u8{0xcd} ** 32)[0..n];
        try testing.expectError(error.PskTooShort, keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", short, "some id"));
        try testing.expectError(error.PskTooShort, keySchedule(Aes128Gcm, 32, .auth_psk, &suite_id, &ss, "", short, "some id"));
    }
    // Exactly Nh bytes is accepted (the floor is inclusive) — and the RFC's
    // own Appendix A PSK vectors are exactly 32 bytes, so a stricter floor
    // would reject the spec's own test vectors.
    _ = try keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", ([_]u8{0xcd} ** 32)[0..32], "some id");
}

test "Context.seal/.open: round trip, seq advances, tampered ct rejected WITHOUT advancing seq" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ss = [_]u8{0x42} ** 32;
    var sender = try keySchedule(Aes128Gcm, 32, .base, &suite_id, &ss, "seq test", "", "");
    var receiver = sender;

    const pt = "attack at dawn";
    var ct: [pt.len + Aes128Gcm.tag_length]u8 = undefined;
    try sender.seal("aad", pt, &ct);
    try testing.expectEqual(@as(u64, 1), sender.seq);

    // Tampered ciphertext: rejected, receiver.seq must NOT advance.
    var bad = ct;
    bad[0] ^= 1;
    var out: [pt.len]u8 = undefined;
    try testing.expectError(error.DecryptionFailed, receiver.open("aad", &bad, &out));
    try testing.expectEqual(@as(u64, 0), receiver.seq);
    // Wrong aad: also rejected.
    try testing.expectError(error.DecryptionFailed, receiver.open("wrong aad", &ct, &out));
    try testing.expectEqual(@as(u64, 0), receiver.seq);
    // Truncated-below-tag ciphertext: typed error, not a panic.
    try testing.expectError(error.DecryptionFailed, receiver.open("aad", ct[0 .. Aes128Gcm.tag_length - 1], out[0..0]));

    // The genuine message still opens at the un-advanced seq.
    try receiver.open("aad", &ct, &out);
    try testing.expectEqualSlices(u8, pt, &out);
    try testing.expectEqual(@as(u64, 1), receiver.seq);
}

test "Context.seal/.open: wrong-length out buffer fails closed with error.InvalidLength (not a debug-only assert), seq unchanged" {
    // I5 hpke<->zig-hpke diff finding: `out.len` used to be a
    // `std.debug.assert`, which ReleaseFast/ReleaseSmall compile out —
    // this test runs under both `zig build test-hpke` (Debug) and
    // `-Doptimize=ReleaseFast`, so it only proves the fix if it passes in
    // BOTH (an assert-based version would pass in Debug and silently
    // misbehave in ReleaseFast).
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ss = [_]u8{0x42} ** 32;
    var sender = try keySchedule(Aes128Gcm, 32, .base, &suite_id, &ss, "", "", "");
    var receiver = sender;

    const pt = "wrong length out";
    var ct_ok: [pt.len + Aes128Gcm.tag_length]u8 = undefined;
    var ct_short: [pt.len + Aes128Gcm.tag_length - 1]u8 = undefined; // one byte too few
    var ct_long: [pt.len + Aes128Gcm.tag_length + 1]u8 = undefined; // one byte too many

    try testing.expectError(error.InvalidLength, sender.seal("aad", pt, &ct_short));
    try testing.expectError(error.InvalidLength, sender.seal("aad", pt, &ct_long));
    try testing.expectEqual(@as(u64, 0), sender.seq); // neither rejected call advanced seq

    // A genuine call with the correct length still works after the two
    // rejections (the guard doesn't wedge the context).
    try sender.seal("aad", pt, &ct_ok);
    try testing.expectEqual(@as(u64, 1), sender.seq);

    var out_short: [pt.len - 1]u8 = undefined;
    var out_long: [pt.len + 1]u8 = undefined;
    try testing.expectError(error.InvalidLength, receiver.open("aad", &ct_ok, &out_short));
    try testing.expectError(error.InvalidLength, receiver.open("aad", &ct_ok, &out_long));
    try testing.expectEqual(@as(u64, 0), receiver.seq); // neither rejected call advanced seq

    var out_ok: [pt.len]u8 = undefined;
    try receiver.open("aad", &ct_ok, &out_ok);
    try testing.expectEqualSlices(u8, pt, &out_ok);
    try testing.expectEqual(@as(u64, 1), receiver.seq);
}

test "Context.seal/.open: fail closed at seq == maxInt(u64) BEFORE producing/consuming a ciphertext" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ss = [_]u8{0x42} ** 32;
    var ctx = try keySchedule(Aes128Gcm, 32, .base, &suite_id, &ss, "", "", "");
    ctx.seq = std.math.maxInt(u64);
    var ct: [1 + Aes128Gcm.tag_length]u8 = undefined;
    try testing.expectError(error.MessageLimitReached, ctx.seal("", "x", &ct));
    var out: [1]u8 = undefined;
    try testing.expectError(error.MessageLimitReached, ctx.open("", &ct, &out));
    try testing.expectEqual(std.math.maxInt(u64), ctx.seq); // unchanged
}

test "sealBase -> openBase: end-to-end round trip on fresh random keys (X25519 + AES-128-GCM)" {
    const dhkem = @import("dhkem.zig");
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const skR = dhkem.X25519Kem.generateKeyPair(io);
    const pt = "one-shot HPKE round trip";
    var ct: [pt.len + Aes128Gcm.tag_length]u8 = undefined;
    const sealed = try sealBase(dhkem.X25519Kem, Aes128Gcm, 32, skR.public_key, io, "round-trip info", "round-trip aad", pt, &ct);

    var out: [pt.len]u8 = undefined;
    try openBase(dhkem.X25519Kem, Aes128Gcm, 32, sealed.enc, skR, "round-trip info", "round-trip aad", &ct, &out);
    try testing.expectEqualSlices(u8, pt, &out);

    // Mismatched info must fail authentication (different key schedule).
    try testing.expectError(error.DecryptionFailed, openBase(dhkem.X25519Kem, Aes128Gcm, 32, sealed.enc, skR, "DIFFERENT info", "round-trip aad", &ct, &out));
}

test "sealBase -> openBase: end-to-end round trip on fresh random keys (P-256 + ChaCha20Poly1305)" {
    // Cross-pairing on purpose: exercises the P-256 KEM path and the
    // ChaCha AEAD width (Nk=32) through the same single-shot wrappers.
    const dhkem = @import("dhkem.zig");
    const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const skR = dhkem.P256Kem.generateKeyPair(io);
    const pt = "p256 + chacha round trip";
    var ct: [pt.len + ChaCha20Poly1305.tag_length]u8 = undefined;
    const sealed = try sealBase(dhkem.P256Kem, ChaCha20Poly1305, 32, skR.public_key, io, "", "", pt, &ct);

    var out: [pt.len]u8 = undefined;
    try openBase(dhkem.P256Kem, ChaCha20Poly1305, 32, sealed.enc, skR, "", "", &ct, &out);
    try testing.expectEqualSlices(u8, pt, &out);
}

test "sealPsk/sealAuth/sealAuthPsk -> matching open: round trip on fresh random keys, and every mismatch rejected" {
    // Round-trip coverage only — these three modes' BYTE-EXACT behaviour is
    // pinned by the RFC 9180 A.1.2/A.1.3/A.1.4 vectors in kat_rfc9180.zig
    // (a round trip alone cannot catch a misreading both sides share).
    // What this test adds is the negative half: each authenticator actually
    // has to match for the open to succeed.
    const dhkem = @import("dhkem.zig");
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const Kem = dhkem.X25519Kem;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const skR = Kem.generateKeyPair(io);
    const skS = Kem.generateKeyPair(io);
    const wrong_sender = Kem.generateKeyPair(io);
    const psk_id = "psk id";
    const wrong_psk = [_]u8{0xcd} ** 32;

    const pt = "single-shot non-base modes";
    var ct: [pt.len + Aes128Gcm.tag_length]u8 = undefined;
    var out: [pt.len]u8 = undefined;

    // mode_psk
    {
        const sealed = try sealPsk(Kem, Aes128Gcm, 32, skR.public_key, io, "info", &test_psk, psk_id, "aad", pt, &ct);
        try openPsk(Kem, Aes128Gcm, 32, sealed.enc, skR, "info", &test_psk, psk_id, "aad", &ct, &out);
        try testing.expectEqualSlices(u8, pt, &out);
        try testing.expectError(error.DecryptionFailed, openPsk(Kem, Aes128Gcm, 32, sealed.enc, skR, "info", &wrong_psk, psk_id, "aad", &ct, &out));
        try testing.expectError(error.DecryptionFailed, openPsk(Kem, Aes128Gcm, 32, sealed.enc, skR, "info", &test_psk, "other id", "aad", &ct, &out));
        // A too-short PSK is rejected by the key schedule before any AEAD work.
        try testing.expectError(error.PskTooShort, sealPsk(Kem, Aes128Gcm, 32, skR.public_key, io, "info", "short", psk_id, "aad", pt, &ct));
    }

    // mode_auth
    {
        const sealed = try sealAuth(Kem, Aes128Gcm, 32, skR.public_key, skS, io, "info", "aad", pt, &ct);
        try openAuth(Kem, Aes128Gcm, 32, sealed.enc, skR, skS.public_key, "info", "aad", &ct, &out);
        try testing.expectEqualSlices(u8, pt, &out);
        // Wrong sender public key: the whole point of the mode.
        try testing.expectError(error.DecryptionFailed, openAuth(Kem, Aes128Gcm, 32, sealed.enc, skR, wrong_sender.public_key, "info", "aad", &ct, &out));
        // And base-mode open must NOT accept an auth-mode ciphertext.
        try testing.expectError(error.DecryptionFailed, openBase(Kem, Aes128Gcm, 32, sealed.enc, skR, "info", "aad", &ct, &out));
    }

    // mode_auth_psk
    {
        const sealed = try sealAuthPsk(Kem, Aes128Gcm, 32, skR.public_key, skS, io, "info", &test_psk, psk_id, "aad", pt, &ct);
        try openAuthPsk(Kem, Aes128Gcm, 32, sealed.enc, skR, skS.public_key, "info", &test_psk, psk_id, "aad", &ct, &out);
        try testing.expectEqualSlices(u8, pt, &out);
        try testing.expectError(error.DecryptionFailed, openAuthPsk(Kem, Aes128Gcm, 32, sealed.enc, skR, wrong_sender.public_key, "info", &test_psk, psk_id, "aad", &ct, &out));
        try testing.expectError(error.DecryptionFailed, openAuthPsk(Kem, Aes128Gcm, 32, sealed.enc, skR, skS.public_key, "info", &wrong_psk, psk_id, "aad", &ct, &out));
        // auth (no PSK) must not open an auth_psk ciphertext: different mode
        // byte in key_schedule_context, hence a different key.
        try testing.expectError(error.DecryptionFailed, openAuth(Kem, Aes128Gcm, 32, sealed.enc, skR, skS.public_key, "info", "aad", &ct, &out));
    }
}

test "single-shot wrappers: P-256 + ChaCha20Poly1305 cross-pairing round-trips in all three non-base modes" {
    // Same cross-pairing rationale as the base-mode P-256/ChaCha test above:
    // proves the wrappers are generic over the KEM's key widths (Npk=65) and
    // the AEAD's key width (Nk=32), not accidentally X25519/AES-specific.
    const dhkem = @import("dhkem.zig");
    const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const Kem = dhkem.P256Kem;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const skR = Kem.generateKeyPair(io);
    const skS = Kem.generateKeyPair(io);
    const pt = "p256 + chacha, non-base modes";
    var ct: [pt.len + ChaCha20Poly1305.tag_length]u8 = undefined;
    var out: [pt.len]u8 = undefined;

    const s1 = try sealPsk(Kem, ChaCha20Poly1305, 32, skR.public_key, io, "", &test_psk, "id", "", pt, &ct);
    try openPsk(Kem, ChaCha20Poly1305, 32, s1.enc, skR, "", &test_psk, "id", "", &ct, &out);
    try testing.expectEqualSlices(u8, pt, &out);

    const s2 = try sealAuth(Kem, ChaCha20Poly1305, 32, skR.public_key, skS, io, "", "", pt, &ct);
    try openAuth(Kem, ChaCha20Poly1305, 32, s2.enc, skR, skS.public_key, "", "", &ct, &out);
    try testing.expectEqualSlices(u8, pt, &out);

    const s3 = try sealAuthPsk(Kem, ChaCha20Poly1305, 32, skR.public_key, skS, io, "", &test_psk, "id", "", pt, &ct);
    try openAuthPsk(Kem, ChaCha20Poly1305, 32, s3.enc, skR, skS.public_key, "", &test_psk, "id", "", &ct, &out);
    try testing.expectEqualSlices(u8, pt, &out);
}
