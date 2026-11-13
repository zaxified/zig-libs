// SPDX-License-Identifier: MIT
//! RFC 9380 hashing to the NIST curves, the part of the P256-SHA256 /
//! P384-SHA384 / P521-SHA512 ciphersuites (RFC 9497 §4.3-§4.5) that neither
//! `std` nor the `p256`/`p384`/`p521` siblings provide:
//!
//!   - `expandMessageXmd` — §5.3.1 over any std SHA-2 hash, any `ell` up to
//!     255 (the SHA-512/64-byte special case in `root.zig` predates it);
//!   - `expandMessageXof` — §5.3.2 over SHAKE256 (decaf448-SHAKE256);
//!   - `Nist(...)` — `hash_to_field` (§5.2, `m = 1`), the simplified SWU map
//!     (§6.6.2) with `sqrt_ratio` for `q = 3 (mod 4)` (Appendix F.2.1.2),
//!     and `hash_to_curve` (§3, `_RO_`: two field elements, two maps, one
//!     addition; `h_eff = 1`, so no cofactor clearing).
//!
//! Built only on the siblings' public `Fe` API (`add`/`sub`/`mul`/`sq`/
//! `invert`/`cMov`/`equivalent`/`isOdd`/`fromBytes`/`fromInt`), so no
//! sibling is edited. Validated against RFC 9380 Appendix J.1.1/J.2.1/J.3.1
//! (every `u[0]`/`u[1]`, `Q0`/`Q1` and `P` of all five messages per curve)
//! and Appendix K.1/K.3 (`h2c_test.zig`).
//!
//! Constant time: the message is SECRET in OPRF use (it is the client's
//! private input, e.g. a password), so nothing below branches on the
//! message, the uniform bytes, `u`, or any field value derived from them —
//! every data-dependent choice is a `cMov`. The only branches are on
//! comptime constants (exponent bits, lengths).

const std = @import("std");

/// An optimization barrier on a byte: the result is `x`, but the compiler
/// can no longer prove it is 0 or 1, so a mask built from it is not turned
/// back into a branch.
pub fn launder(x: u8) u8 {
    var v = x;
    asm volatile (""
        : [v] "+r" (v),
    );
    return v;
}

/// RFC 9380 §5.3.1 `expand_message_xmd(msg, DST, len_in_bytes)` with hash
/// `Hash` (a `std.crypto.hash.sha2` type). `msg` is given as consecutive
/// parts (`parts[0] || parts[1] || ...`, never concatenated in memory).
/// `len_in_bytes` and `dst` are comptime, so the §5.3.1 step-1 bounds
/// (`ell <= 255`, `len <= 65535`, `len(DST) <= 255`) are compile errors,
/// not runtime refusals. Same shape as `bls12_381`'s
/// `expandMessageXmdParts`, generic over the hash.
pub fn expandMessageXmd(
    comptime Hash: type,
    comptime len_in_bytes: usize,
    parts: []const []const u8,
    comptime dst: []const u8,
) [len_in_bytes]u8 {
    const b_in_bytes = Hash.digest_length;
    const s_in_bytes = Hash.block_length;
    const ell = comptime (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
    comptime {
        if (len_in_bytes == 0 or len_in_bytes > 65535 or ell > 255) @compileError("expand_message_xmd: len_in_bytes out of range");
        if (dst.len == 0 or dst.len > 255) @compileError("expand_message_xmd: DST must be 1..255 bytes");
    }
    const dst_prime = dst ++ [1]u8{@intCast(dst.len)};
    const z_pad = @as([s_in_bytes]u8, @splat(0));
    const l_i_b_str = [2]u8{ @intCast(len_in_bytes >> 8), @intCast(len_in_bytes & 0xff) };

    var h0 = Hash.init(.{});
    h0.update(&z_pad);
    for (parts) |part| h0.update(part);
    h0.update(&l_i_b_str);
    h0.update(&[1]u8{0x00});
    h0.update(dst_prime);
    var b0: [b_in_bytes]u8 = undefined;
    h0.final(&b0);

    var out: [len_in_bytes]u8 = undefined;
    var b_prev: [b_in_bytes]u8 = undefined;
    var h1 = Hash.init(.{});
    h1.update(&b0);
    h1.update(&[1]u8{0x01});
    h1.update(dst_prime);
    h1.final(&b_prev);
    {
        const n = @min(b_in_bytes, len_in_bytes);
        @memcpy(out[0..n], b_prev[0..n]);
    }
    comptime var i: usize = 2;
    inline while (i <= ell) : (i += 1) {
        var xored: [b_in_bytes]u8 = undefined;
        for (&xored, b0, b_prev) |*o, x, y| o.* = x ^ y;
        var hi = Hash.init(.{});
        hi.update(&xored);
        hi.update(&[1]u8{@intCast(i)});
        hi.update(dst_prime);
        hi.final(&b_prev);
        const offset = (i - 1) * b_in_bytes;
        const n = @min(b_in_bytes, len_in_bytes - offset);
        @memcpy(out[offset..][0..n], b_prev[0..n]);
    }
    std.crypto.secureZero(u8, &b0);
    std.crypto.secureZero(u8, &b_prev);
    return out;
}

/// RFC 9380 §5.3.2 `expand_message_xof` with SHAKE256 (the decaf448-SHAKE256
/// expander, RFC 9497 §4.2), message as parts, comptime length and DST.
pub fn expandMessageXof(
    comptime len_in_bytes: usize,
    parts: []const []const u8,
    comptime dst: []const u8,
) [len_in_bytes]u8 {
    comptime {
        if (len_in_bytes > 65535) @compileError("expand_message_xof: len_in_bytes out of range");
        if (dst.len == 0 or dst.len > 255) @compileError("expand_message_xof: DST must be 1..255 bytes");
    }
    var h = std.crypto.hash.sha3.Shake256.init(.{});
    for (parts) |part| h.update(part);
    h.update(&[2]u8{ @intCast(len_in_bytes >> 8), @intCast(len_in_bytes & 0xff) });
    h.update(dst ++ [1]u8{@intCast(dst.len)});
    var out: [len_in_bytes]u8 = undefined;
    h.squeeze(&out);
    return out;
}

/// `OS2IP(bytes) mod m` for a big-endian `bytes` of even length `L` into a
/// field type `F` with `F.fromBytes(.big)`/`mul`/`add`: the two halves are
/// each below `2^(4L) < m` (asserted at comptime), so each is a canonical
/// element as is, and `hi * 2^(4L) + lo` is one multiply and one add — no
/// wide reduction needed, nothing data-dependent. `r` is `2^(4L) mod m` as
/// an element of `F`. `fromBytes` cannot fail on a value below `m`; its
/// error arm returns zero so no panic path exists.
pub fn reduceHalves(comptime F: type, comptime enc_len: usize, comptime L: usize, bytes: *const [L]u8, r: F) F {
    comptime std.debug.assert(L % 2 == 0 and L / 2 <= enc_len);
    const half = L / 2;
    var hi_buf = @as([enc_len]u8, @splat(0));
    var lo_buf = @as([enc_len]u8, @splat(0));
    @memcpy(hi_buf[enc_len - half ..], bytes[0..half]);
    @memcpy(lo_buf[enc_len - half ..], bytes[half..]);
    const hi = F.fromBytes(hi_buf, .big) catch F.zero;
    const lo = F.fromBytes(lo_buf, .big) catch F.zero;
    std.crypto.secureZero(u8, &hi_buf);
    std.crypto.secureZero(u8, &lo_buf);
    return hi.mul(r).add(lo);
}

/// The big-endian `[n]u8` encoding of a comptime integer `x < 2^(8n)`;
/// call it in a `comptime` context.
pub fn beBytes(comptime n: usize, comptime x: u1024) [n]u8 {
    @setEvalBranchQuota(10_000);
    var out: [n]u8 = undefined;
    var v = x;
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(v & 0xff);
        v >>= 8;
    }
    if (v != 0) @compileError("beBytes: value does not fit");
    return out;
}

/// Hash-to-curve for a short-Weierstrass NIST curve `y^2 = x^3 - 3x + B`
/// over `GF(p)`, `p = 3 (mod 4)`, with suite parameters from RFC 9380 §8.2-§8.4.
///
///   - `Point`: the sibling's projective point type (fields `x`, `y`, `z` of
///     type `Fe`, method `add`).
///   - `p`: the field prime; `z`: the SSWU constant `Z` (negative);
///     `c2`: `sqrt(-Z) mod p` (precomputed; `c2^2 == -Z` is a unit test);
///   - `L`: the `hash_to_field` length; `Hash`: the XMD hash.
pub fn Nist(
    comptime Point: type,
    comptime p: u1024,
    comptime z: comptime_int,
    comptime c2_int: comptime_int,
    comptime L: usize,
    comptime Hash: type,
) type {
    return struct {
        pub const Fe = Point.Fe;
        const field_len = Fe.encoded_length;
        const A = Fe.fromInt(@intCast(p - 3)) catch unreachable; // comptime
        pub const Z = Fe.fromInt(@intCast(p - (-z))) catch unreachable; // comptime
        pub const c2 = Fe.fromInt(c2_int) catch unreachable; // comptime
        const B = Point.B;
        const R = Fe.fromInt(@intCast((@as(u1024, 1) << (4 * L)) % p)) catch unreachable; // comptime
        /// `c1 = (p - 3) / 4` of Appendix F.2.1.2.
        const c1 = (p - 3) / 4;

        /// `CMOV(a, b, c)`: `b` if `c == 1`, else `a`, without a branch.
        /// Not the sibling's `Fe.cMov`: `p521`'s compiles to a conditional
        /// jump on `c` at ReleaseFast (ctgrind `voprf/p521-client`,
        /// 2026-11-13; `p256`'s is laundered, `p384`'s measured clean), so
        /// this selects over the element's bytes with a mask the optimizer
        /// cannot see through (`launder`). zig-libs: drop once p521 Fe.cMov is
        /// laundered.
        fn sel(a: Fe, b: Fe, c: u1) Fe {
            var r = a;
            const mask: u8 = 0 -% launder(@as(u8, c));
            const rb = std.mem.asBytes(&r);
            const bb = std.mem.asBytes(&b);
            for (rb, bb) |*x, y| x.* ^= (x.* ^ y) & mask;
            return r;
        }

        /// `x^c1` by left-to-right square-and-multiply over the PUBLIC
        /// exponent's bits (the branch is on a comptime constant only).
        fn powC1(x: Fe) Fe {
            const e: u1024 = c1;
            const bits = comptime 1024 - @clz(e);
            var r = Fe.one;
            var i: usize = bits;
            while (i > 0) {
                i -= 1;
                r = r.sq();
                if (((e >> @intCast(i)) & 1) == 1) r = r.mul(x);
            }
            return r;
        }

        /// Appendix F.2.1.2 `sqrt_ratio(u, v)` for `q = 3 (mod 4)`.
        fn sqrtRatio(u: Fe, v: Fe, y_out: *Fe) u1 {
            var tv1 = v.sq(); // 1
            const tv2 = u.mul(v); // 2
            tv1 = tv1.mul(tv2); // 3
            var y1 = powC1(tv1); // 4
            y1 = y1.mul(tv2); // 5
            const y2 = y1.mul(c2); // 6
            var tv3 = y1.sq(); // 7
            tv3 = tv3.mul(v); // 8
            const is_qr: u1 = @intFromBool(tv3.equivalent(u)); // 9
            y_out.* = sel(y2, y1, is_qr); // 10
            return is_qr;
        }

        pub const Affine = struct { x: Fe, y: Fe };

        /// §6.6.2 `map_to_curve_simple_swu(u)`, the straight-line version.
        pub fn mapToCurve(u: Fe) Affine {
            var tv1 = u.sq(); // 1
            tv1 = Z.mul(tv1); // 2
            var tv2 = tv1.sq(); // 3
            tv2 = tv2.add(tv1); // 4
            var tv3 = tv2.add(Fe.one); // 5
            tv3 = B.mul(tv3); // 6
            const tv2_nz: u1 = 1 - @as(u1, @intFromBool(tv2.isZero()));
            var tv4 = sel(Z, tv2.neg(), tv2_nz); // 7
            tv4 = A.mul(tv4); // 8
            tv2 = tv3.sq(); // 9
            var tv6 = tv4.sq(); // 10
            var tv5 = A.mul(tv6); // 11
            tv2 = tv2.add(tv5); // 12
            tv2 = tv2.mul(tv3); // 13
            tv6 = tv6.mul(tv4); // 14
            tv5 = B.mul(tv6); // 15
            tv2 = tv2.add(tv5); // 16
            var x = tv1.mul(tv3); // 17
            var y1: Fe = undefined;
            const is_gx1_square = sqrtRatio(tv2, tv6, &y1); // 18
            var y = tv1.mul(u); // 19
            y = y.mul(y1); // 20
            x = sel(x, tv3, is_gx1_square); // 21
            y = sel(y, y1, is_gx1_square); // 22
            const e1: u1 = ~(@as(u1, @intFromBool(u.isOdd())) ^ @as(u1, @intFromBool(y.isOdd()))); // 23
            y = sel(y.neg(), y, e1); // 24
            x = x.mul(tv4.invert()); // 25
            return .{ .x = x, .y = y };
        }

        /// §5.2 `hash_to_field(msg, count)` with `m = 1`.
        pub fn hashToField(comptime count: usize, parts: []const []const u8, comptime dst: []const u8) [count]Fe {
            var uniform = expandMessageXmd(Hash, count * L, parts, dst);
            defer std.crypto.secureZero(u8, &uniform);
            var out: [count]Fe = undefined;
            inline for (0..count) |i| out[i] = reduceHalves(Fe, field_len, L, uniform[i * L ..][0..L], R);
            return out;
        }

        /// §3 `hash_to_curve(msg)` (the `_RO_` encoding): never the
        /// identity for these curves except with negligible probability, but
        /// the caller still checks (RFC 9497 §3.3.1 InvalidInputError).
        pub fn hashToCurve(parts: []const []const u8, comptime dst: []const u8) Point {
            const u = hashToField(2, parts, dst);
            const q0 = mapToCurve(u[0]);
            const q1 = mapToCurve(u[1]);
            const p0 = Point{ .x = q0.x, .y = q0.y, .z = Fe.one };
            const p1 = Point{ .x = q1.x, .y = q1.y, .z = Fe.one };
            return p0.add(p1);
        }
    };
}
