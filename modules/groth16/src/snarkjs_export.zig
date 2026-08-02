// SPDX-License-Identifier: MIT
//! snarkjs JSON exporter — the piece that closes SPEC.md's one named blind
//! spot (§5, corrected below): the sibling `bn254` verifier is a complete
//! ALGEBRAIC oracle (any wrong QAP coefficient, witness index, sign, or
//! randomizer makes it reject), but it is the SAME implementation's own
//! decoder reading the SAME implementation's own encoder — it cannot see a
//! serialization convention (coordinate order, endianness, compression flag)
//! that both sides agreed on wrongly. This file renders our `bn254`-typed
//! `Proof`/`VerifyingKey`/public-input values into the exact JSON shape
//! `snarkjs groth16 verify` parses, so an independent, foreign
//! implementation (iden3's `snarkjs`, Apache-2.0, run via `bunx`, never
//! vendored) can sit in judgment of our encoding. See `snarkjs_kat_test.zig`
//! for the frozen run and its verdict.
//!
//! ## The JSON shape (reverse-engineered from `snarkjs@0.7.6`'s bundled
//! `build/snarkjs.js`, the actual installed code, not guessed from docs)
//!
//! `groth16Verify` (around its `IC0 = curve.G1.fromObject(...)` calls) reads
//! `vk_alpha_1`/`vk_beta_2`/`vk_gamma_2`/`vk_delta_2`/`IC` from the
//! verification key and `pi_a`/`pi_b`/`pi_c` from the proof, each field
//! parsed by `ffjavascript`'s `WasmCurve.fromObject`/`WasmField2.fromObject`/
//! `WasmField1.fromObject`:
//!   - A field element (`Fp`/`Fr`) is a JSON STRING of decimal digits
//!     (`WasmField1.toObject`/`fromObject`, no `0x`, no sign for our
//!     always-canonical-reduced values).
//!   - A `G1` point is a 3-element array `[x, y, z]`; `z` defaults to `"1"`
//!     for affine points (`WasmCurve.fromObject`, `a.length==3` branch else
//!     `z = F.one`) and `["0","1","0"]` encodes the point at infinity
//!     (`WasmCurve.toObject`'s `isZero` branch).
//!   - A `G2` point is `[[x.c0,x.c1], [y.c0,y.c1], ["1","0"]]` — each `Fp2`
//!     coordinate is a 2-element `[c0, c1]` array in MATH order (real part
//!     first: `WasmField2.toObject`/`fromObject` reads/writes index 0 then
//!     index 1 with NO swap). This is the SAME `(c0, c1)` order the sibling
//!     `bn254/src/groth16.zig` KAT doc comment already documents for its own
//!     Dark Forest vectors ("MATH order... the opposite of `g2.zig`'s EIP-197
//!     byte-codec order") — confirmed here independently by reading
//!     snarkjs's own source rather than assumed to match.
//!   - `verification_key.json` additionally carries `"protocol":"groth16"`,
//!     `"curve":"bn128"` (accepted aliases: `"bn128"`/`"bn254"`/`"altbn128"`,
//!     case/separator-insensitive — `getCurveFromName`'s `normalizeName`),
//!     `"nPublic": <public input count>`. `proof.json` carries the same
//!     `protocol`/`curve` pair (unused by `groth16Verify` itself but part of
//!     `snarkjs`'s own export shape).
//!   - `public.json` is a bare JSON array of decimal-digit-string public
//!     inputs, no wrapper object.
//!
//! Field-element decimal conversion (`decimalBytes` below) is schoolbook
//! base-256→base-10 long division over the type's existing big-endian
//! `toBytes()` — plain bignum arithmetic, not a cryptographic operation, and
//! not routed through any external library.

const std = @import("std");
const bn254 = @import("bn254");
const field = @import("field.zig");
const Fr = field.Fr;
const Fp = bn254.Fp;
const G1 = bn254.G1;
const G2 = bn254.G2;

/// Maximum decimal digits for a 256-bit big-endian value: `ceil(256 *
/// log10(2)) = 78`, rounded up for headroom.
pub const max_decimal_digits = 80;

fn isAllZero(bytes: []const u8) bool {
    for (bytes) |b| {
        if (b != 0) return false;
    }
    return true;
}

/// Converts a big-endian byte array (any length) to a decimal string written
/// into `buf` (`buf.len >= max_decimal_digits` required). Returns the
/// written slice — no leading zeros, `"0"` for an all-zero input. Repeated
/// schoolbook long division of the big-endian byte string by 10, collecting
/// remainders least-significant-digit first, then reversed.
pub fn decimalBytes(be: []const u8, buf: []u8) []const u8 {
    std.debug.assert(buf.len >= max_decimal_digits);
    var work_buf: [32]u8 = undefined;
    std.debug.assert(be.len <= work_buf.len);
    @memcpy(work_buf[0..be.len], be);
    const work = work_buf[0..be.len];

    var digits: [max_decimal_digits]u8 = undefined;
    var n: usize = 0;
    while (!isAllZero(work)) {
        var rem: u16 = 0;
        for (work) |*byte| {
            const cur = rem * @as(u16, 256) + @as(u16, byte.*);
            byte.* = @intCast(cur / 10);
            rem = @intCast(cur % 10);
        }
        std.debug.assert(n < max_decimal_digits);
        digits[n] = '0' + @as(u8, @intCast(rem));
        n += 1;
    }
    if (n == 0) {
        buf[0] = '0';
        return buf[0..1];
    }
    for (0..n) |i| buf[i] = digits[n - 1 - i];
    return buf[0..n];
}

/// Decimal-string encoding of an `Fp` element (base field coordinate).
pub fn fpDecimal(fp: Fp, buf: []u8) []const u8 {
    return decimalBytes(&fp.toBytes(), buf);
}

/// Decimal-string encoding of an `Fr` element (scalar / public input).
pub fn frDecimal(fr: Fr, buf: []u8) []const u8 {
    return decimalBytes(&fr.toBytes(), buf);
}

fn writeFpDecimal(w: *std.Io.Writer, fp: Fp) !void {
    var buf: [max_decimal_digits]u8 = undefined;
    try w.writeAll(fpDecimal(fp, &buf));
}

/// Writes a `G1.Affine` point as snarkjs's `[x, y, "1"]` (or `["0","1","0"]`
/// at infinity).
pub fn writeG1(w: *std.Io.Writer, p: G1.Affine) !void {
    if (p.infinity) {
        try w.writeAll("[\"0\",\"1\",\"0\"]");
        return;
    }
    try w.writeAll("[\"");
    try writeFpDecimal(w, p.x);
    try w.writeAll("\",\"");
    try writeFpDecimal(w, p.y);
    try w.writeAll("\",\"1\"]");
}

/// Writes a `G2.Affine` point as snarkjs's `[[x.c0,x.c1],[y.c0,y.c1],
/// ["1","0"]]` — `(c0, c1)` MATH order per this file's module doc comment,
/// NOT the EIP-197 byte-codec's imaginary-first order.
pub fn writeG2(w: *std.Io.Writer, p: G2.Affine) !void {
    if (p.infinity) {
        try w.writeAll("[[\"0\",\"0\"],[\"1\",\"0\"],[\"0\",\"0\"]]");
        return;
    }
    try w.writeAll("[[\"");
    try writeFpDecimal(w, p.x.c0);
    try w.writeAll("\",\"");
    try writeFpDecimal(w, p.x.c1);
    try w.writeAll("\"],[\"");
    try writeFpDecimal(w, p.y.c0);
    try w.writeAll("\",\"");
    try writeFpDecimal(w, p.y.c1);
    try w.writeAll("\"],[\"1\",\"0\"]]");
}

/// Renders `vk` as `verification_key.json`'s exact byte shape (compact, no
/// whitespace — `snarkjs`'s own JSON parser doesn't care about formatting).
pub fn verifyingKeyJson(allocator: std.mem.Allocator, vk: bn254.Groth16VerifyingKey) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    const w = &aw.writer;

    try w.writeAll("{\"protocol\":\"groth16\",\"curve\":\"bn128\",\"nPublic\":");
    try w.print("{d}", .{vk.ic.len - 1});
    try w.writeAll(",\"vk_alpha_1\":");
    try writeG1(w, vk.alpha_g1);
    try w.writeAll(",\"vk_beta_2\":");
    try writeG2(w, vk.beta_g2);
    try w.writeAll(",\"vk_gamma_2\":");
    try writeG2(w, vk.gamma_g2);
    try w.writeAll(",\"vk_delta_2\":");
    try writeG2(w, vk.delta_g2);
    try w.writeAll(",\"IC\":[");
    for (vk.ic, 0..) |p, i| {
        if (i != 0) try w.writeAll(",");
        try writeG1(w, p);
    }
    try w.writeAll("]}");

    return aw.toOwnedSlice();
}

/// Renders `proof` as `proof.json`'s exact byte shape.
pub fn proofJson(allocator: std.mem.Allocator, proof: bn254.Groth16Proof) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    const w = &aw.writer;

    try w.writeAll("{\"pi_a\":");
    try writeG1(w, proof.a);
    try w.writeAll(",\"pi_b\":");
    try writeG2(w, proof.b);
    try w.writeAll(",\"pi_c\":");
    try writeG1(w, proof.c);
    try w.writeAll(",\"protocol\":\"groth16\",\"curve\":\"bn128\"}");

    return aw.toOwnedSlice();
}

/// Renders `public_inputs` as `public.json`'s exact byte shape: a bare array
/// of decimal-digit strings, in order.
pub fn publicJson(allocator: std.mem.Allocator, public_inputs: []const Fr) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    const w = &aw.writer;

    try w.writeAll("[");
    for (public_inputs, 0..) |pi, i| {
        if (i != 0) try w.writeAll(",");
        try w.writeAll("\"");
        var buf: [max_decimal_digits]u8 = undefined;
        try w.writeAll(frDecimal(pi, &buf));
        try w.writeAll("\"");
    }
    try w.writeAll("]");

    return aw.toOwnedSlice();
}

// ── tests ────────────────────────────────────────────────────────────────

test "decimalBytes: zero encodes as \"0\"" {
    var buf: [max_decimal_digits]u8 = undefined;
    const zero = [_]u8{0} ** 32;
    try std.testing.expectEqualStrings("0", decimalBytes(&zero, &buf));
}

test "decimalBytes: one encodes as \"1\"" {
    var buf: [max_decimal_digits]u8 = undefined;
    var one = [_]u8{0} ** 32;
    one[31] = 1;
    try std.testing.expectEqualStrings("1", decimalBytes(&one, &buf));
}

test "decimalBytes: 256 encodes as \"256\" (multi-digit, byte boundary)" {
    var buf: [max_decimal_digits]u8 = undefined;
    var v = [_]u8{0} ** 32;
    v[30] = 1;
    v[31] = 0;
    try std.testing.expectEqualStrings("256", decimalBytes(&v, &buf));
}

test "decimalBytes round-trips Fr.toBytes for a handful of small scalars" {
    var buf: [max_decimal_digits]u8 = undefined;
    inline for (.{ 1, 2, 5, 25, 12345 }) |n| {
        const fr = field.frFromU64(n);
        try std.testing.expectEqualStrings(
            std.fmt.comptimePrint("{d}", .{n}),
            frDecimal(fr, &buf),
        );
    }
}

test "writeG1 renders the G1 generator as snarkjs's [x,y,\"1\"] shape" {
    const allocator = std.testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    try writeG1(&aw.writer, G1.Affine.generator);
    // G1 generator is (1, 2) — EIP-196.
    try std.testing.expectEqualStrings("[\"1\",\"2\",\"1\"]", aw.writer.buffered());
}

test "writeG1 renders infinity as [\"0\",\"1\",\"0\"]" {
    const allocator = std.testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    try writeG1(&aw.writer, .{ .x = Fp.zero, .y = Fp.zero, .infinity = true });
    try std.testing.expectEqualStrings("[\"0\",\"1\",\"0\"]", aw.writer.buffered());
}

test "publicJson renders a bare decimal-string array" {
    const allocator = std.testing.allocator;
    const inputs = [_]Fr{ field.frFromU64(9), field.frFromU64(16), field.frFromU64(49) };
    const json = try publicJson(allocator, &inputs);
    defer allocator.free(json);
    try std.testing.expectEqualStrings("[\"9\",\"16\",\"49\"]", json);
}
