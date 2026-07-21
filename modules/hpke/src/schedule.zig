// SPDX-License-Identifier: MIT
//! HPKE key schedule + encryption context (RFC 9180 §5): `KeySchedule`
//! (§5.1, mode/PSK/info -> `Context`), `Context.seal`/`.open`/
//! `.exportSecret` (§5.2/§5.3), and the single-shot `sealBase`/`openBase`
//! wrappers (§6.1). All REAL (crypto-implementation pass done) —
//! KAT-validated against RFC 9180 Appendix A.1's published
//! key/base_nonce/exporter_secret, all 6 encryption tuples, and all 3
//! exported values (see `kat_rfc9180.zig`). The KDF is hard-wired to
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

/// RFC 9180 §5.1: `KeySchedule`'s own precondition failures — an
/// auth/auth_psk call missing the PSK the mode requires, or vice versa
/// (§5.1 Table 1's mode/PSK-requirement matrix), which this module DOES
/// validate up front (a pure "did the caller pass the right combination of
/// optional params" check, not a crypto judgment call).
pub const KeyScheduleError = error{
    /// `mode` is `.psk`/`.auth_psk` but `psk`/`psk_id` was empty, or
    /// `mode` is `.base`/`.auth` but a non-empty `psk`/`psk_id` was
    /// supplied (RFC 9180 §5.1 "VerifyPSKInputs").
    InconsistentPsk,
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
/// KAT: reproduces RFC 9180 A.1.1's `key`/`base_nonce`/`exporter_secret`
/// end-to-end from `shared_secret` (see `kat_rfc9180.zig`).
///
/// Recipe (RFC 9180 §5.1, `suite_id = suite.suiteId(kem_id, kdf_id,
/// aead_id)` — the OUTER suite id, not the KEM's):
/// ```text
/// VerifyPSKInputs(mode, psk, psk_id)   // KeyScheduleError.InconsistentPsk on a mismatch, see that error's doc comment
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
    const encapped = try Kem.encapDeterministic(pkR, eph);
    const suite_id = comptime suiteIdOf(Kem, Aead);
    var ctx = try keySchedule(Aead, Nh, .base, &suite_id, &encapped.shared_secret, info, "", "");
    try ctx.seal(aad, pt, out);
    return .{ .enc = encapped.enc };
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
    const shared_secret = try Kem.decap(enc, skR);
    const suite_id = comptime suiteIdOf(Kem, Aead);
    var ctx = try keySchedule(Aead, Nh, .base, &suite_id, &shared_secret, info, "", "");
    try ctx.open(aad, ct, out);
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

test "keySchedule: VerifyPSKInputs rejects every inconsistent mode/psk combination" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ss = [_]u8{0x42} ** 32;
    // base mode with a PSK supplied.
    try testing.expectError(error.InconsistentPsk, keySchedule(Aes128Gcm, 32, .base, &suite_id, &ss, "", "some psk", "some id"));
    // psk mode with no PSK.
    try testing.expectError(error.InconsistentPsk, keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", "", ""));
    // psk without psk_id (and vice versa).
    try testing.expectError(error.InconsistentPsk, keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", "some psk", ""));
    try testing.expectError(error.InconsistentPsk, keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", "", "some id"));
    // Consistent combinations construct fine.
    _ = try keySchedule(Aes128Gcm, 32, .base, &suite_id, &ss, "", "", "");
    _ = try keySchedule(Aes128Gcm, 32, .psk, &suite_id, &ss, "", "some psk", "some id");
    _ = try keySchedule(Aes128Gcm, 32, .auth, &suite_id, &ss, "", "", "");
    _ = try keySchedule(Aes128Gcm, 32, .auth_psk, &suite_id, &ss, "", "some psk", "some id");
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
