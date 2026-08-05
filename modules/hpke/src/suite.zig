// SPDX-License-Identifier: MIT
//! HPKE (RFC 9180) suite plumbing: the id constants, `suite_id`/KEM
//! `suite_id` construction (§4/§7.2.1), `I2OSP`/`OS2IP` (§1.3 conventions,
//! reused from the wider IETF corpus — RFC 8017/PKCS#1's integer<->octet
//! string primitives), and `LabeledExtract`/`LabeledExpand` (§4, the domain
//! separation every other HPKE derivation is built from). Everything in
//! this file is REAL — this is the composition std doesn't ship, not a
//! primitive std is missing (HKDF-Extract/Expand themselves are
//! `std.crypto.kdf.hkdf.Hkdf(Hmac)`, used here via their public API, never
//! reimplemented).
//!
//! Model: RFC 9180 §1.3 (notation), §4 (cryptographic dependencies),
//! §7.2.1 (`suite_id` construction), and the LabeledExtract/LabeledExpand
//! definitions threaded through §4/§5.1/§5.2/§7.1.3.

const std = @import("std");

// ── §1.3 conventions: I2OSP / OS2IP ─────────────────────────────────────
//
// RFC 9180 borrows these directly from RFC 8017 (PKCS#1) §4: I2OSP
// converts a nonnegative integer to a big-endian octet string of a fixed
// length; OS2IP is its inverse. HPKE only ever calls I2OSP(x, 2) (kem_id/
// kdf_id/aead_id, and the `L` length prefix in LabeledExpand), so `n <= 8`
// (fits a u64) covers every real use in this module; the general form is
// kept because RFC 9180 quotes the general definition, and a narrower
// `i2osp2` alone would hide that this is the same primitive PKCS#1 names.

/// RFC 9180 §1.3 / RFC 8017 §4.1: `I2OSP(x, xLen)` — encode `value` as a
/// big-endian octet string of exactly `n` bytes. Asserts `value` fits (the
/// spec defines I2OSP as failing, "integer too large", when it doesn't;
/// every call site in this module passes a compile-time-known-safe value,
/// so a debug assert is the right shape here rather than a runtime error).
pub fn i2osp(comptime n: usize, value: u64) [n]u8 {
    comptime std.debug.assert(n >= 1 and n <= 8);
    if (n < 8) std.debug.assert(value < (@as(u64, 1) << @intCast(n * 8)));
    var out: [n]u8 = undefined;
    var v = value;
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        out[i] = @truncate(v);
        v >>= 8;
    }
    return out;
}

/// RFC 9180 §1.3 / RFC 8017 §4.2: `OS2IP(X)` — decode a big-endian octet
/// string as a nonnegative integer. `bytes.len <= 8` (fits a u64); every
/// HPKE use of OS2IP is on a 2-byte id/length field.
pub fn os2ip(bytes: []const u8) u64 {
    std.debug.assert(bytes.len <= 8);
    var v: u64 = 0;
    for (bytes) |b| v = (v << 8) | b;
    return v;
}

// ── §4 / §7.2.1: KEM, KDF, AEAD identifiers ─────────────────────────────

/// RFC 9180 §7.1 Table 2 — DHKEM identifiers this module names (the two
/// std can build without a C dependency: X25519 and P-256 raw ECDH; see
/// `dhkem.zig`). Other spec-registered KEMs (P-384, P-521, X448) are
/// simply not instantiated here — nothing in this file is X25519/P-256
/// specific.
pub const KemId = enum(u16) {
    dhkem_x25519_hkdf_sha256 = 0x0020,
    dhkem_p256_hkdf_sha256 = 0x0010,
    _,
};

/// RFC 9180 §7.2 Table 3 — KDF identifiers. All three are instantiated:
/// `labeledExtract`/`labeledExpand` below were always generic over any
/// `std.crypto.kdf.hkdf.Hkdf(Hmac)` instantiation (this file never
/// hardcoded a hash), and `schedule.zig`'s key schedule now dispatches on
/// `Nh` (`schedule.KdfOf`) to pick HKDF-SHA256/384/512 — see that file for
/// the outer-KDF-vs-KEM's-own-KDF distinction (RFC 9180 §4.1 vs §7.2:
/// a DHKEM's internal KDF is fixed by its `kem_id`, independent of the
/// ciphersuite's `kdf_id` this enum names).
pub const KdfId = enum(u16) {
    hkdf_sha256 = 0x0001,
    hkdf_sha384 = 0x0002,
    hkdf_sha512 = 0x0003,
    _,
};

/// RFC 9180 §7.3 Table 5 — AEAD identifiers. `export_only` (0xFFFF) names
/// HPKE's "no bulk encryption, `Context.export` only" mode — the id is
/// reserved here, though `schedule.Context` is only instantiated over the
/// three real AEAD types (an export-only context shape is future work).
pub const AeadId = enum(u16) {
    aes128gcm = 0x0001,
    aes256gcm = 0x0002,
    chacha20poly1305 = 0x0003,
    export_only = 0xffff,
    _,
};

/// RFC 9180 §5.1 Table 1 — the four HPKE modes. `psk`/`auth_psk` need a
/// pre-shared key; `auth`/`auth_psk` need the sender's static KEM keypair
/// (DHKEM's `AuthEncap`/`AuthDecap`, see `dhkem.zig`).
pub const Mode = enum(u8) {
    base = 0x00,
    psk = 0x01,
    auth = 0x02,
    auth_psk = 0x03,
};

// ── §7.2.1: suite_id construction ───────────────────────────────────────

/// RFC 9180 §7.2.1: the HPKE ciphersuite id threaded into every
/// `LabeledExtract`/`LabeledExpand` call in the KEY SCHEDULE (§5.1) and
/// export (§5.3) — NOT the one used inside the KEM itself (see
/// `kemSuiteId`). `suite_id = "HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2)
/// || I2OSP(aead_id,2)` (10 bytes).
pub fn suiteId(kem_id: u16, kdf_id: u16, aead_id: u16) [10]u8 {
    var out: [10]u8 = undefined;
    out[0..4].* = "HPKE".*;
    out[4..6].* = i2osp(2, kem_id);
    out[6..8].* = i2osp(2, kdf_id);
    out[8..10].* = i2osp(2, aead_id);
    return out;
}

/// RFC 9180 §4.1: the DHKEM's OWN suite id, used only inside
/// `ExtractAndExpand` (`dhkem.zig`'s ​`Encap`/`Decap`/`AuthEncap`/
/// `AuthDecap`) — distinct from `suiteId` above (which folds in kdf_id/
/// aead_id too). `kem_suite_id = "KEM" || I2OSP(kem_id,2)` (5 bytes).
pub fn kemSuiteId(kem_id: u16) [5]u8 {
    var out: [5]u8 = undefined;
    out[0..3].* = "KEM".*;
    out[3..5].* = i2osp(2, kem_id);
    return out;
}

// ── §4: LabeledExtract / LabeledExpand ───────────────────────────────────

/// RFC 9180 §4: `LabeledExtract(salt, label, ikm) = Extract(salt,
/// concat("HPKE-v1", suite_id, label, ikm))`. `Hkdf` is a
/// `std.crypto.kdf.hkdf.Hkdf(Hmac)` instantiation (e.g. `HkdfSha256`).
/// `suite_id` is either `suiteId(...)` (key-schedule/export derivations)
/// or `kemSuiteId(...)` (KEM-internal derivations) depending on call site
/// — this function is suite-id-agnostic, the caller picks. Streams the
/// labeled IKM through `Hkdf`'s incremental HMAC (`extractInit`/`update`/
/// `final`) rather than concatenating into a fixed buffer, so `ikm` (a KEM
/// DH output, or an application-supplied PSK) may be any length.
pub fn labeledExtract(
    comptime Hkdf: type,
    suite_id: []const u8,
    salt: []const u8,
    label: []const u8,
    ikm: []const u8,
) [Hkdf.prk_length]u8 {
    var hmac_state = Hkdf.extractInit(salt);
    hmac_state.update("HPKE-v1");
    hmac_state.update(suite_id);
    hmac_state.update(label);
    hmac_state.update(ikm);
    var prk: [Hkdf.prk_length]u8 = undefined;
    hmac_state.final(&prk);
    return prk;
}

/// Labeled-info assembly overflowed the internal scratch buffer — only
/// possible with an unusually large `info`/`exporter_context` (every
/// suite_id/label used by this module is a handful of bytes; the buffer
/// below is sized generously for realistic application `info` strings).
pub const LabeledExpandError = error{LabelTooLong};

/// RFC 9180 §4: `LabeledExpand(prk, label, info, L) = Expand(prk,
/// concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info), L)`. Writes
/// exactly `out.len` bytes (`L = out.len`). Unlike `labeledExtract`, the
/// labeled info must be ONE contiguous slice (`Hkdf.expand`'s `ctx`
/// parameter is re-hashed per output block, so it can't be streamed
/// incrementally) — assembled here via a bounded `std.Io.Writer.fixed`
/// scratch buffer, `error.LabelTooLong` if it doesn't fit rather than a
/// silent truncation or a panic on caller-influenced input.
pub fn labeledExpand(
    comptime Hkdf: type,
    suite_id: []const u8,
    prk: [Hkdf.prk_length]u8,
    label: []const u8,
    info: []const u8,
    out: []u8,
) LabeledExpandError!void {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    w.writeInt(u16, std.math.cast(u16, out.len) orelse return error.LabelTooLong, .big) catch return error.LabelTooLong;
    w.writeAll("HPKE-v1") catch return error.LabelTooLong;
    w.writeAll(suite_id) catch return error.LabelTooLong;
    w.writeAll(label) catch return error.LabelTooLong;
    w.writeAll(info) catch return error.LabelTooLong;
    Hkdf.expand(out, w.buffered(), prk);
}

// ── tests (real — pure arithmetic / composition, no crypto core needed) ──

const testing = std.testing;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

test "i2osp/os2ip round-trip" {
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x20 }, &i2osp(2, 0x0020));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, &i2osp(2, 0x0100));
    try testing.expectEqual(@as(u64, 0x0020), os2ip(&i2osp(2, 0x0020)));
    try testing.expectEqual(@as(u64, 0xffff), os2ip(&i2osp(2, 0xffff)));
}

test "suiteId: HPKE || kem_id || kdf_id || aead_id, 10 bytes" {
    // RFC 9180 Appendix A.1: kem_id=0x0020 (X25519), kdf_id=0x0001
    // (HKDF-SHA256), aead_id=0x0001 (AES-128-GCM).
    const got = suiteId(0x0020, 0x0001, 0x0001);
    const want = "HPKE" ++ [_]u8{ 0x00, 0x20 } ++ [_]u8{ 0x00, 0x01 } ++ [_]u8{ 0x00, 0x01 };
    try testing.expectEqualSlices(u8, want, &got);
}

test "kemSuiteId: KEM || kem_id, 5 bytes" {
    const got = kemSuiteId(0x0020);
    const want = "KEM" ++ [_]u8{ 0x00, 0x20 };
    try testing.expectEqualSlices(u8, want, &got);
}

test "meta smoke: Mode ordinals match RFC 9180 Table 1" {
    try testing.expectEqual(@as(u8, 0x00), @intFromEnum(Mode.base));
    try testing.expectEqual(@as(u8, 0x01), @intFromEnum(Mode.psk));
    try testing.expectEqual(@as(u8, 0x02), @intFromEnum(Mode.auth));
    try testing.expectEqual(@as(u8, 0x03), @intFromEnum(Mode.auth_psk));
}

test "labeledExtract/labeledExpand: RFC 9180 A.1.1 key_schedule_context + secret, byte-exact" {
    // A.1.1 publishes `shared_secret` directly (no need to run DHKEM
    // Encap to get it), so the base-mode key-schedule's
    // mode||psk_id_hash||info_hash and its `secret` derivation are both
    // exercisable through nothing but this file's LabeledExtract/
    // LabeledExpand — no `dhkem`/`schedule` involvement at all (those
    // paths get their own end-to-end KATs in kat_rfc9180.zig).
    const suite_id = suiteId(0x0020, 0x0001, 0x0001);
    const info = &[_]u8{ 0x4f, 0x64, 0x65, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x47, 0x72, 0x65, 0x63, 0x69, 0x61, 0x6e, 0x20, 0x55, 0x72, 0x6e };

    // psk_id_hash = LabeledExtract(suite_id, "", "psk_id_hash", "") — base
    // mode's psk_id is the empty string.
    const psk_id_hash = labeledExtract(HkdfSha256, &suite_id, "", "psk_id_hash", "");
    // info_hash = LabeledExtract(suite_id, "", "info_hash", info)
    const info_hash = labeledExtract(HkdfSha256, &suite_id, "", "info_hash", info);

    // key_schedule_context = mode(1) || psk_id_hash(32) || info_hash(32)
    var ksc: [65]u8 = undefined;
    ksc[0] = @intFromEnum(Mode.base);
    ksc[1..33].* = psk_id_hash;
    ksc[33..65].* = info_hash;

    const want_ksc = hexBytes(65, "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449");
    try testing.expectEqualSlices(u8, &want_ksc, &ksc);

    // secret = LabeledExtract(shared_secret, "secret", psk) — base mode's
    // psk is the empty string; shared_secret is the A.1.1 vector value
    // (published directly, so this does NOT need to run Encap).
    const shared_secret = hexBytes(32, "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    const secret = labeledExtract(HkdfSha256, &suite_id, &shared_secret, "secret", "");
    const want_secret = hexBytes(32, "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
    try testing.expectEqualSlices(u8, &want_secret, &secret);

    // key/base_nonce/exporter_secret = LabeledExpand(secret, ..., ksc, N)
    var key: [16]u8 = undefined;
    try labeledExpand(HkdfSha256, &suite_id, secret, "key", &ksc, &key);
    try testing.expectEqualSlices(u8, &hexBytes(16, "4531685d41d65f03dc48f6b8302c05b0"), &key);

    var base_nonce: [12]u8 = undefined;
    try labeledExpand(HkdfSha256, &suite_id, secret, "base_nonce", &ksc, &base_nonce);
    try testing.expectEqualSlices(u8, &hexBytes(12, "56d890e5accaaf011cff4b7d"), &base_nonce);

    var exporter_secret: [32]u8 = undefined;
    try labeledExpand(HkdfSha256, &suite_id, secret, "exp", &ksc, &exporter_secret);
    try testing.expectEqualSlices(u8, &hexBytes(32, "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8"), &exporter_secret);
}

/// Test-only hex decode helper (this module's KAT constants are inlined as
/// hex strings straight from the RFC text, not pre-converted byte arrays).
fn hexBytes(comptime n: usize, hex: *const [n * 2]u8) [n]u8 {
    @setEvalBranchQuota(10_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}
