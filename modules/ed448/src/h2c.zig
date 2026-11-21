// SPDX-License-Identifier: MIT
//! RFC 9380 hash-to-curve for edwards448: the suites
//! `edwards448_XOF:SHAKE256_ELL2_RO_` (`hashToCurve`) and
//! `edwards448_XOF:SHAKE256_ELL2_NU_` (`encodeToCurve`) of §8.6.
//!
//!   1. `hash_to_field` (§5.2): `expand_message_xof` with SHAKE256 (§5.3.2),
//!      `k = 224`, `L = 84` bytes per element, `m = 1`; a DST over 255 bytes
//!      is reduced to `SHAKE256("H2C-OVERSIZE-DST-" || DST, 56)` (§5.3.3).
//!   2. `map_to_curve`: Elligator 2 on curve448 (`Z = −1`, straight-line form
//!      of Appendix G.2.3), then RFC 7748 §4.2's 4-isogeny onto edwards448
//!      (Appendix G.2.4's fraction form, no inversion).
//!   3. `clear_cofactor`: `h_eff = 4` (`Point.clearCofactor`).
//!
//! Not constant-time by requirement in the sense that the inputs are
//! public in every common use (VOPRF/VRF/BLS-style messages); the map is
//! straight-line apart from the final point arithmetic, as RFC 9380 writes
//! it. Anchored by RFC 9380 Appendix J.7 (`u`, `Q`, `P` for five messages
//! per suite), reproduced first by an RFC model in Python.

const std = @import("std");
const field = @import("field.zig");
const ed = @import("ed448.zig");

const Fe = field.Fe;
const Point = ed.Point;
const Shake256 = std.crypto.hash.sha3.Shake256;

/// `L = ceil((ceil(log2(p)) + k) / 8)` with `k = 224`.
pub const field_l = 84;
/// `ceil(2k/8)`: the length of a reduced oversize DST.
const oversize_dst_length = 56;

/// RFC 9380 §5.3.2 `expand_message_xof` with SHAKE256, `k = 224`, over a
/// message given as consecutive parts; any DST length (§5.3.3 above 255),
/// `len_in_bytes` 1..65535.
pub fn expandMessageXof(comptime len_in_bytes: usize, parts: []const []const u8, dst: []const u8) [len_in_bytes]u8 {
    comptime std.debug.assert(len_in_bytes > 0 and len_in_bytes <= 65535);
    var reduced: [oversize_dst_length]u8 = undefined;
    const tag: []const u8 = if (dst.len > 255) blk: {
        var r = Shake256.init(.{});
        r.update("H2C-OVERSIZE-DST-");
        r.update(dst);
        r.squeeze(&reduced);
        break :blk &reduced;
    } else dst;
    var h = Shake256.init(.{});
    for (parts) |part| h.update(part);
    var lib: [2]u8 = undefined;
    std.mem.writeInt(u16, &lib, len_in_bytes, .big);
    h.update(&lib);
    h.update(tag);
    h.update(&[_]u8{@intCast(tag.len)});
    var out: [len_in_bytes]u8 = undefined;
    h.squeeze(&out);
    return out;
}

/// A 28-byte big-endian value (< 2^224 < p) as a field element.
fn fe28(be: *const [28]u8) Fe {
    var le: [field.encoded_bytes]u8 = @splat(0);
    for (be, 0..) |b, i| le[27 - i] = b;
    return Fe.fromBytes(le) catch unreachable; // < 2^224
}

/// `2^224 mod p` (= 2^224, below p).
const two_224: Fe = blk: {
    var le: [field.encoded_bytes]u8 = @splat(0);
    le[28] = 1;
    break :blk Fe.fromBytes(le) catch unreachable;
};

/// `OS2IP(bytes) mod p` for 84 big-endian bytes: `hi·2^448 + mid·2^224 +
/// lo` with `2^448 ≡ 2^224 + 1 (mod p)`.
fn reduce84(bytes: *const [field_l]u8) Fe {
    const hi = fe28(bytes[0..28]);
    const mid = fe28(bytes[28..56]);
    const lo = fe28(bytes[56..84]);
    return hi.mul(two_224).add(hi).add(mid.mul(two_224)).add(lo);
}

/// RFC 9380 §5.2 `hash_to_field(msg, count)` over GF(p), `m = 1`, `L = 84`.
pub fn hashToField(comptime count: usize, parts: []const []const u8, dst: []const u8) [count]Fe {
    const uniform = expandMessageXof(count * field_l, parts, dst);
    var out: [count]Fe = undefined;
    for (&out, 0..) |*e, i| e.* = reduce84(uniform[i * field_l ..][0..field_l]);
    return out;
}

/// `(p − 3) / 4`, big-endian (the exponent of G.2.3 step 15).
const c1_be: [field.encoded_bytes]u8 = blk: {
    var b: [field.encoded_bytes]u8 = undefined;
    const v: u448 = @intCast(((@as(u456, 1) << 448) - (@as(u456, 1) << 224) - 1 - 3) / 4);
    std.mem.writeInt(u448, &b, v, .big);
    break :blk b;
};

/// `J = 156326`.
const curve_j: Fe = Fe.one.mulSmall(156326);

/// `map_to_curve_elligator2_curve448(u)` (Appendix G.2.3): `(xn, xd, y)`
/// with `(xn/xd, y)` on curve448 (`yd = 1`).
fn elligator2Curve448(u: Fe) struct { xn: Fe, xd: Fe, y: Fe } {
    var tv1 = u.square();
    const e1 = tv1.eql(Fe.one);
    tv1 = Fe.ctSelect(e1, Fe.zero, tv1);
    const xd = Fe.one.sub(tv1);
    const x1n = curve_j.neg();
    var tv2 = xd.square();
    const gxd = tv2.mul(xd);
    var gx1 = curve_j.neg().mul(tv1);
    gx1 = gx1.mul(x1n);
    gx1 = gx1.add(tv2);
    gx1 = gx1.mul(x1n);
    var tv3 = gxd.square();
    tv2 = gx1.mul(gxd);
    tv3 = tv3.mul(tv2);
    var y1 = tv3.pow(c1_be);
    y1 = y1.mul(tv2);
    const x2n = tv1.neg().mul(x1n);
    var y2 = y1.mul(u);
    y2 = Fe.ctSelect(e1, Fe.zero, y2);
    tv2 = y1.square().mul(gxd);
    const e2 = tv2.eql(gx1);
    const xn = Fe.ctSelect(e2, x1n, x2n);
    var y = Fe.ctSelect(e2, y1, y2);
    const e3 = y.isOdd();
    y = Fe.ctSelect(e2 != e3, y.neg(), y);
    return .{ .xn = xn, .xd = xd, .y = y };
}

/// `map_to_curve_elligator2_edwards448(u)` (Appendix G.2.4): Elligator 2 on
/// curve448 and RFC 7748's 4-isogeny onto edwards448, as a projective
/// point (`X = xEn·yEd, Y = yEn·xEd, Z = xEd·yEd`). Not yet in the
/// prime-order subgroup.
pub fn mapToCurve(u: Fe) Point {
    const m = elligator2Curve448(u);
    const xn = m.xn;
    const xd = m.xd;
    const yn = m.y; // yd = 1
    const xn2 = xn.square();
    const xd2 = xd.square();
    const xd4 = xd2.square();
    const yn2 = yn.square();
    var x_en = xn2.sub(xd2);
    var tv2 = x_en.sub(xd2);
    x_en = x_en.mul(xd2).mul(yn).mulSmall(4); // · yd (= 1)
    tv2 = tv2.mul(xn2); // · yd² (= 1)
    const tv3 = yn2.mulSmall(4);
    var tv1 = tv3.add(Fe.one).mul(xd4);
    var x_ed = tv1.add(tv2);
    tv2 = tv2.mul(xn);
    const tv4 = xn.mul(xd4);
    var y_en = tv3.sub(Fe.one).mul(tv4).sub(tv2);
    tv1 = xn2.add(xd2).mul(xd2).mul(xd).mul(yn2).mulSmall(2).neg();
    var y_ed = tv2.add(tv1);
    y_ed = y_ed.add(tv4); // tv4 · yd² (= 1)
    const e = x_ed.mul(y_ed).isZero();
    x_en = Fe.ctSelect(e, Fe.zero, x_en);
    x_ed = Fe.ctSelect(e, Fe.one, x_ed);
    y_en = Fe.ctSelect(e, Fe.one, y_en);
    y_ed = Fe.ctSelect(e, Fe.one, y_ed);
    return .{ .x = x_en.mul(y_ed), .y = y_en.mul(x_ed), .z = x_ed.mul(y_ed) };
}

/// `hash_to_curve(msg)`, suite `edwards448_XOF:SHAKE256_ELL2_RO_`: a point
/// of the prime-order subgroup.
pub fn hashToCurve(msg: []const u8, dst: []const u8) Point {
    return hashToCurveParts(&.{msg}, dst);
}

/// `hashToCurve` over a message given as consecutive parts.
pub fn hashToCurveParts(parts: []const []const u8, dst: []const u8) Point {
    const u = hashToField(2, parts, dst);
    return mapToCurve(u[0]).add(mapToCurve(u[1])).clearCofactor();
}

/// `encode_to_curve(msg)`, suite `edwards448_XOF:SHAKE256_ELL2_NU_`: one
/// field element, one map. Not uniform (RFC 9380 §10.4).
pub fn encodeToCurve(msg: []const u8, dst: []const u8) Point {
    return mapToCurve(hashToField(1, &.{msg}, dst)[0]).clearCofactor();
}
