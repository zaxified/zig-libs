// SPDX-License-Identifier: MIT
//! The five RFC 9497 §4 ciphersuites as group backends for `protocol.zig`.
//!
//! Each backend is a namespace with the same declarations (checked by
//! `protocol.Protocol`'s comptime interface assert):
//!
//!   - `identifier`, `Ne`, `Ns`, `Nh`, `Lw` (bytes `HashToScalar` reduces),
//!     `burn_scale` (multiplier on the dead-stack burn sizes, `burn.zig`);
//!   - `Point`, `base`;
//!   - `hashToGroup(parts, dst)` (may return the identity; the caller
//!     rejects it), `hashToScalar(parts, dst)`, `reduceWide(*[Lw]u8)`;
//!   - `hash(parts)` — the suite's `Hash` over a concatenation, `Nh` bytes;
//!   - `encode`/`decode` (§4 Serialize/DeserializeElement: `decode` refuses
//!     non-canonical encodings AND the identity), `isIdentity`, `add`;
//!   - `mulSecret`/`mulBaseSecret` (constant-time, no error to branch on),
//!     `mulPublic`/`mulBasePublic` (wire data; `error.IdentityElement` on an
//!     identity product, a genuine fail-closed check on peer input);
//!   - `sAdd`/`sSub`/`sMul`/`sInvert`/`sCanonical` on serialized scalars.
//!
//! Scalars are carried serialized (`[Ns]u8`) as in RFC 9497: little-endian
//! for ristretto255/decaf448, big-endian (I2OSP) for the NIST curves.

const std = @import("std");
const ct25519 = @import("ct25519");
const decaf448 = @import("decaf448");
const p256 = @import("p256");
const p384 = @import("p384");
const p521 = @import("p521");
const h2c = @import("h2c.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Shake256 = std.crypto.hash.sha3.Shake256;

pub const IdentityError = error{IdentityElement};
pub const ElementError = error{InvalidElement};
pub const ScalarError = error{InvalidScalar};

fn shaHash(comptime H: type, parts: []const []const u8) [H.digest_length]u8 {
    var h = H.init(.{});
    for (parts) |part| h.update(part);
    var out: [H.digest_length]u8 = undefined;
    h.final(&out);
    return out;
}

// ── §4.1 ristretto255-SHA512 ─────────────────────────────────────────────

pub const Ristretto255Sha512 = struct {
    pub const Point = std.crypto.ecc.Ristretto255;
    const scalar = Point.scalar;
    pub const identifier = "ristretto255-SHA512";
    pub const Ne = 32;
    pub const Ns = 32;
    pub const Nh = 64;
    pub const Lw = 64;
    pub const burn_scale = 1;
    pub const base = Point.basePoint;

    /// `hash_to_ristretto255` (RFC 9380 Appendix B): 64 XMD bytes, then the
    /// RFC 9496 §4.3.4 one-way map (`fromUniform`).
    pub fn hashToGroup(parts: []const []const u8, comptime dst: []const u8) Point {
        return Point.fromUniform(h2c.expandMessageXmd(Sha512, 64, parts, dst));
    }
    pub fn hashToScalar(parts: []const []const u8, comptime dst: []const u8) [Ns]u8 {
        return scalar.reduce64(h2c.expandMessageXmd(Sha512, 64, parts, dst));
    }
    pub fn reduceWide(wide: *const [Lw]u8) [Ns]u8 {
        return scalar.reduce64(wide.*);
    }
    pub fn hash(parts: []const []const u8) [Nh]u8 {
        return shaHash(Sha512, parts);
    }
    pub fn encode(p: Point) [Ne]u8 {
        return p.toBytes();
    }
    pub fn decode(b: [Ne]u8) ElementError!Point {
        const p = Point.fromBytes(b) catch return error.InvalidElement;
        p.rejectIdentity() catch return error.InvalidElement;
        return p;
    }
    pub fn isIdentity(p: Point) bool {
        p.rejectIdentity() catch return true;
        return false;
    }
    pub fn add(a: Point, b: Point) Point {
        return a.add(b);
    }
    /// `ct25519`: std's ladder without its identity-rejecting tail.
    pub fn mulSecret(p: Point, s: *const [Ns]u8) Point {
        return ct25519.mulRistretto(p, s.*);
    }
    pub fn mulBaseSecret(s: *const [Ns]u8) Point {
        return ct25519.mulRistrettoBase(s.*);
    }
    pub fn mulPublic(p: Point, s: [Ns]u8) IdentityError!Point {
        return p.mul(s) catch error.IdentityElement;
    }
    pub fn mulBasePublic(s: [Ns]u8) IdentityError!Point {
        return base.mul(s) catch error.IdentityElement;
    }
    pub fn sAdd(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
        return scalar.add(a, b);
    }
    pub fn sSub(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
        return scalar.sub(a, b);
    }
    pub fn sMul(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
        return scalar.mul(a, b);
    }
    pub fn sInvert(a: [Ns]u8) [Ns]u8 {
        return scalar.Scalar.fromBytes(a).invert().toBytes();
    }
    pub fn sCanonical(a: [Ns]u8) ScalarError!void {
        scalar.rejectNonCanonical(a) catch return error.InvalidScalar;
    }
};

// ── §4.2 decaf448-SHAKE256 ───────────────────────────────────────────────

pub const Decaf448Shake256 = struct {
    pub const Point = decaf448.Element;
    const scalar = decaf448.scalar;
    pub const identifier = "decaf448-SHAKE256";
    pub const Ne = 56;
    pub const Ns = 56;
    pub const Nh = 64;
    pub const Lw = 64;
    pub const burn_scale = 2;
    pub const base = Point.generator;

    /// `hash_to_decaf448` (RFC 9380 Appendix C): 112 XOF bytes, then the
    /// sibling's RFC 9496 §5.3.4 one-way map.
    pub fn hashToGroup(parts: []const []const u8, comptime dst: []const u8) Point {
        var uniform = h2c.expandMessageXof(112, parts, dst);
        defer std.crypto.secureZero(u8, &uniform);
        return decaf448.element.oneWayMap(uniform);
    }
    pub fn hashToScalar(parts: []const []const u8, comptime dst: []const u8) [Ns]u8 {
        var uniform = h2c.expandMessageXof(64, parts, dst);
        defer std.crypto.secureZero(u8, &uniform);
        return scalar.reduce(64, uniform);
    }
    pub fn reduceWide(wide: *const [Lw]u8) [Ns]u8 {
        return scalar.reduce(64, wide.*);
    }
    /// RFC 9497 §4.2: `Hash` is SHAKE256 with a 64-byte output.
    pub fn hash(parts: []const []const u8) [Nh]u8 {
        var h = Shake256.init(.{});
        for (parts) |part| h.update(part);
        var out: [Nh]u8 = undefined;
        h.squeeze(&out);
        return out;
    }
    pub fn encode(p: Point) [Ne]u8 {
        return p.encode();
    }
    pub fn decode(b: [Ne]u8) ElementError!Point {
        const p = Point.decode(b) catch return error.InvalidElement;
        if (p.equals(Point.identity)) return error.InvalidElement;
        return p;
    }
    pub fn isIdentity(p: Point) bool {
        return p.equals(Point.identity);
    }
    pub fn add(a: Point, b: Point) Point {
        return a.add(b);
    }
    /// The sibling's multiply returns a value (no error union), constant
    /// time in the scalar (its own ctgrind harness).
    pub fn mulSecret(p: Point, s: *const [Ns]u8) Point {
        return p.scalarMul(s);
    }
    pub fn mulBaseSecret(s: *const [Ns]u8) Point {
        return base.scalarMul(s);
    }
    pub fn mulPublic(p: Point, s: [Ns]u8) IdentityError!Point {
        const r = p.scalarMul(&s);
        if (r.equals(Point.identity)) return error.IdentityElement;
        return r;
    }
    pub fn mulBasePublic(s: [Ns]u8) IdentityError!Point {
        return mulPublic(base, s);
    }
    pub fn sAdd(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
        return scalar.add(a, b);
    }
    pub fn sSub(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
        return scalar.sub(a, b);
    }
    pub fn sMul(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
        return scalar.mul(a, b);
    }
    pub fn sInvert(a: [Ns]u8) [Ns]u8 {
        return scalar.invert(a);
    }
    pub fn sCanonical(a: [Ns]u8) ScalarError!void {
        scalar.rejectNonCanonical(a) catch return error.InvalidScalar;
    }
};

// ── §4.3-§4.5 the NIST curves ────────────────────────────────────────────

/// One backend for P-256 / P-384 / P-521: SEC1 compressed elements
/// (`Ne = Ns + 1`), big-endian scalars, RFC 9380 `_XMD:SHA-*_SSWU_RO_`
/// hash-to-curve from `h2c.zig`, and `hash_to_field` reduction mod the
/// group order for `HashToScalar`.
///
/// The secret multiplies go through the sibling's constant-time `mulInto`,
/// which ends with ONE branch on the product's identity verdict (laundered,
/// "the verdict the error reveals anyway" — the siblings' own ECDH shape).
/// For a validated non-identity point that verdict is `s == 0 (mod n)`;
/// voprf maps it to the identity element instead of an error (the same
/// "a degenerate secret is a value" contract as ristretto255), so the
/// verdict is not reported through any voprf API.
fn Nist(
    comptime Curve: type,
    comptime scalar_mod: type,
    comptime ident: []const u8,
    comptime Hash: type,
    comptime L: usize,
    comptime z: comptime_int,
    comptime c2: comptime_int,
    comptime point_first: bool,
) type {
    return struct {
        pub const Point = Curve;
        const Scalar = scalar_mod.Scalar;
        pub const identifier = ident;
        pub const Ns = scalar_mod.encoded_length;
        pub const Ne = Ns + 1;
        pub const Nh = Hash.digest_length;
        pub const Lw = L;
        pub const burn_scale = 2;
        pub const base = Curve.basePoint;
        const n: u1024 = scalar_mod.field_order;
        const H2c = h2c.Nist(Curve, Curve.Fe.field_order, z, c2, L, Hash);
        pub const hash_to_curve = H2c;

        pub fn hashToGroup(parts: []const []const u8, comptime dst: []const u8) Point {
            return H2c.hashToCurve(parts, dst);
        }
        pub fn hashToScalar(parts: []const []const u8, comptime dst: []const u8) [Ns]u8 {
            var uniform = h2c.expandMessageXmd(Hash, L, parts, dst);
            defer std.crypto.secureZero(u8, &uniform);
            return reduceWide(&uniform);
        }
        /// `OS2IP(wide) mod n` (RFC 9380 §5.2 step 7 over the scalar field).
        pub fn reduceWide(wide: *const [Lw]u8) [Ns]u8 {
            const r = Scalar.fromBytes(comptime h2c.beBytes(Ns, (@as(u1024, 1) << (4 * L)) % n), .big) catch Scalar.zero;
            return h2c.reduceHalves(Scalar, Ns, L, wide, r).toBytes(.big);
        }
        pub fn hash(parts: []const []const u8) [Nh]u8 {
            return shaHash(Hash, parts);
        }
        /// SEC1 compressed. The identity has no compressed form; it can only
        /// arise from a degenerate secret (see the type comment) and encodes
        /// as `Ne` zero bytes, which `decode` refuses.
        pub fn encode(p: Point) [Ne]u8 {
            // Branch-free: the element can be secret (the client's unblinded
            // element), so the identity verdict only masks the bytes.
            var out = p.toCompressedSec1();
            const mask: u8 = 0 -% h2c.launder(@intFromBool(p.z.isZero()));
            for (&out) |*o| o.* &= ~mask;
            return out;
        }
        pub fn decode(b: [Ne]u8) ElementError!Point {
            if (b[0] != 0x02 and b[0] != 0x03) return error.InvalidElement;
            const p = Curve.fromSec1(&b) catch return error.InvalidElement;
            p.rejectIdentity() catch return error.InvalidElement;
            return p;
        }
        pub fn isIdentity(p: Point) bool {
            p.rejectIdentity() catch return true;
            return false;
        }
        pub fn add(a: Point, b: Point) Point {
            return a.add(b);
        }
        pub fn mulSecret(p: Point, s: *const [Ns]u8) Point {
            var out: Point = undefined;
            if (point_first) {
                p.mulInto(&out, s, .big) catch return Curve.identityElement;
            } else {
                Curve.mulInto(&out, p, s, .big) catch return Curve.identityElement;
            }
            return out;
        }
        pub fn mulBaseSecret(s: *const [Ns]u8) Point {
            return mulSecret(base, s);
        }
        pub fn mulPublic(p: Point, s: [Ns]u8) IdentityError!Point {
            return p.mulPublic(s, .big) catch error.IdentityElement;
        }
        pub fn mulBasePublic(s: [Ns]u8) IdentityError!Point {
            return mulPublic(base, s);
        }
        fn sc(a: [Ns]u8) Scalar {
            // Every scalar reaching here is canonical (validated at the API
            // boundary or produced by a reduction), so the canonical-range
            // check inside `fromBytes` always passes; the arm only keeps the
            // call panic-free. (P-256's `fromBytes` is std's: its range check
            // is one branch on the verdict — ctgrind counts it, it reveals
            // nothing. std's `fromBytes64` reduction does the same check
            // three times, so it is not the cleaner road.)
            return Scalar.fromBytes(a, .big) catch Scalar.zero;
        }
        pub fn sAdd(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
            return sc(a).add(sc(b)).toBytes(.big);
        }
        pub fn sSub(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
            return sc(a).sub(sc(b)).toBytes(.big);
        }
        pub fn sMul(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
            return sc(a).mul(sc(b)).toBytes(.big);
        }
        pub fn sInvert(a: [Ns]u8) [Ns]u8 {
            return sc(a).invert().toBytes(.big);
        }
        pub fn sCanonical(a: [Ns]u8) ScalarError!void {
            scalar_mod.rejectNonCanonical(a, .big) catch return error.InvalidScalar;
        }
    };
}

/// §4.3 P256-SHA256: RFC 9380 §8.2 `P256_XMD:SHA-256_SSWU_RO_` (`Z = -10`, `L = 48`).
pub const P256Sha256 = Nist(p256.P256, p256.scalar, "P256-SHA256", Sha256, 48, -10, 0xda538e3be1d89b99c978fc675180aab27b8d1ff84c55d5b62ccd3427e433c47f, true);

/// §4.4 P384-SHA384: RFC 9380 §8.3 `P384_XMD:SHA-384_SSWU_RO_` (`Z = -12`, `L = 72`).
pub const P384Sha384 = Nist(p384.P384, p384.scalar, "P384-SHA384", Sha384, 72, -12, 0x2accb4a656b0249c71f0500e83da2fdd7f98e383d68b53871f872fcb9ccb80c53c0de1f8a80f7e1914e2ec69f5a626b3, false);

/// §4.5 P521-SHA512: RFC 9380 §8.4 `P521_XMD:SHA-512_SSWU_RO_` (`Z = -4`, `L = 98`).
pub const P521Sha512 = Nist(p521.P521, p521.scalar, "P521-SHA512", Sha512, 98, -4, 0x2, false);
