// SPDX-License-Identifier: MIT
//! The key-schedule KDFs as types (RFC 9180 §7.2 Table 3 + draft-ietf-hpke-pq):
//! the three two-stage HKDFs and the four one-stage XOFs (SHAKE128/256,
//! TurboSHAKE128/256). Every `setup*`/`seal*`/`open*`/`Context` entry point
//! takes its KDF as `comptime Nh: anytype` — either one of these types or,
//! as before, the integer `Nh` (32/48/64 = HKDF-SHA256/384/512, `Of`).
//!
//! A one-stage KDF has no Extract/Expand split: draft-ietf-hpke-hpke §4.4
//! `LabeledDerive(ikm, label, context, L) = Derive(ikm || "HPKE-v1" ||
//! suite_id || lengthPrefixed(label) || I2OSP(L, 2) || context, L)`, where
//! `Derive` is the XOF's output of length `L`. Ported from Go 1.26
//! `crypto/hpke/kdf.go` (`shakeKDF.labeledDerive`, BSD-3-Clause, see NOTICE).

const std = @import("std");
const suite = @import("suite.zig");
const sha3 = std.crypto.hash.sha3;

/// A two-stage HKDF suite (`LabeledExtract` + `LabeledExpand`, RFC 9180 §4).
fn TwoStage(comptime H: type, comptime id: suite.KdfId) type {
    return struct {
        pub const kdf_id: u16 = @backingInt(id);
        pub const Nh: usize = H.prk_length;
        pub const one_stage = false;
        pub const Hkdf = H;
    };
}

pub const HkdfSha256 = TwoStage(std.crypto.kdf.hkdf.HkdfSha256, .hkdf_sha256);
pub const HkdfSha384 = TwoStage(std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384), .hkdf_sha384);
pub const HkdfSha512 = TwoStage(std.crypto.kdf.hkdf.HkdfSha512, .hkdf_sha512);

/// `LabeledDerive`'s inputs went past the one-stage limits: `L` above 65,535
/// (it is encoded in two bytes, draft-ietf-hpke-hpke §5.3), or a
/// length-prefixed field (`psk`, `psk_id`, `info`) above 65,535 bytes (§7.2.1).
pub const DeriveError = error{LabelTooLong};

/// The largest `L` / length-prefixed field a one-stage KDF accepts.
pub const max_one_stage_len: usize = 0xffff;

/// A one-stage XOF suite. `Xof` is a std SHAKE/TurboSHAKE type (`init(.{})`,
/// `update`, `squeeze`).
fn OneStage(comptime X: type, comptime id: suite.KdfId, comptime nh: usize) type {
    return struct {
        pub const kdf_id: u16 = @backingInt(id);
        pub const Nh: usize = nh;
        pub const one_stage = true;
        pub const Xof = X;

        /// `LabeledDerive(ikm, label, context, out.len)` with `ikm` and
        /// `context` each given as a list of parts, hashed in order (the key
        /// schedule's `secrets` and `context` are concatenations of
        /// length-prefixed fields, streamed here instead of assembled in a
        /// buffer, so `info` has no scratch-size limit).
        pub fn labeledDerive(
            out: []u8,
            suite_id: []const u8,
            ikm: []const []const u8,
            label: []const u8,
            context: []const []const u8,
        ) DeriveError!void {
            if (out.len > max_one_stage_len or label.len > max_one_stage_len) return error.LabelTooLong;
            var x = Xof.init(.{});
            defer std.crypto.secureZero(u8, std.mem.asBytes(&x));
            for (ikm) |part| x.update(part);
            x.update("HPKE-v1");
            x.update(suite_id);
            x.update(&suite.i2osp(2, label.len));
            x.update(label);
            x.update(&suite.i2osp(2, out.len));
            for (context) |part| x.update(part);
            x.squeeze(out);
        }
    };
}

pub const Shake128 = OneStage(sha3.Shake128, .shake128, 32);
pub const Shake256 = OneStage(sha3.Shake256, .shake256, 64);
/// TurboSHAKE with the default domain-separation byte 0x1F (RFC 9861), as the
/// draft-ietf-hpke-pq vectors use.
pub const TurboShake128 = OneStage(sha3.TurboShake128(null), .turboshake128, 32);
pub const TurboShake256 = OneStage(sha3.TurboShake256(null), .turboshake256, 64);

/// The KDF type behind an entry point's `Nh` argument: a KDF type above is
/// itself, an integer is the RFC 9180 HKDF of that width (the API before the
/// one-stage KDFs, kept so `Context(Aead, 32)` still means HKDF-SHA256).
pub fn Of(comptime nh: anytype) type {
    if (@TypeOf(nh) == type) {
        if (!@hasDecl(nh, "kdf_id") or !@hasDecl(nh, "one_stage"))
            @compileError("hpke: " ++ @typeName(nh) ++ " is not an hpke.kdf type");
        return nh;
    }
    return switch (nh) {
        32 => HkdfSha256,
        48 => HkdfSha384,
        64 => HkdfSha512,
        else => @compileError("hpke: no RFC 9180 KDF registered for Nh=" ++ std.fmt.comptimePrint("{d}", .{nh}) ++ " (valid: 32 HKDF-SHA256, 48 HKDF-SHA384, 64 HKDF-SHA512, or an hpke.kdf type)"),
    };
}

const testing = std.testing;

test "Of: integers map to the RFC 9180 HKDFs, types pass through" {
    try testing.expect(Of(32) == HkdfSha256);
    try testing.expect(Of(48) == HkdfSha384);
    try testing.expect(Of(64) == HkdfSha512);
    try testing.expect(Of(Shake256) == Shake256);
    try testing.expectEqual(@as(usize, 48), HkdfSha384.Nh);
    try testing.expectEqual(@as(u16, 0x0013), TurboShake256.kdf_id);
}

test "labeledDerive: L and label above 65535 are refused" {
    var big: [max_one_stage_len + 1]u8 = undefined;
    try testing.expectError(error.LabelTooLong, Shake128.labeledDerive(&big, "x", &.{}, "l", &.{}));
    try Shake128.labeledDerive(big[0..max_one_stage_len], "x", &.{}, "l", &.{});
}

test "labeledDerive: parts are a concatenation (split points do not matter)" {
    var a: [40]u8 = undefined;
    var b: [40]u8 = undefined;
    try Shake256.labeledDerive(&a, "sid", &.{"abcdef"}, "lab", &.{"ctx1ctx2"});
    try Shake256.labeledDerive(&b, "sid", &.{ "abc", "", "def" }, "lab", &.{ "ctx1", "ctx2" });
    try testing.expectEqualSlices(u8, &a, &b);
}
