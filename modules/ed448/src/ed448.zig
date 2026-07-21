// SPDX-License-Identifier: MIT
//! Ed448 — EdDSA over edwards448 (RFC 8032 §5.2), the "SigEd448"
//! signature scheme built on `field.zig`'s shared `Fp448` and this file's
//! own `Point`/scalar-mod-`L` (`scalar.zig`) machinery. Mirrors
//! `std.crypto.sign.Ed25519`'s shape (`KeyPair`, `Signature`,
//! `sign`/`verify`) one curve family up, with SHAKE256 (not SHA-512) as
//! the hash and the RFC 8032 §5.1's "dom4" domain-separation prefix
//! (`"SigEd448" || octet(phflag) || octet(len(ctx)) || ctx`) folded into
//! every hash call.
//!
//! **Status: implemented.** The `dom4` domain-separation framing
//! (`absorbDom4`), the `Signature`/`PublicKey`/`SecretKey` wire codecs,
//! the `sign`/`verify` orchestration (transcribed directly from RFC 8032
//! §5.2.5/§5.2.6/§5.2.7), AND the full curve arithmetic (`Point.add`/
//! `dbl`/`mul`/`toBytes`/`fromBytes`, on `field.zig`'s implemented
//! `Fp448` and `scalar.zig`'s implemented mod-`L` arithmetic) are real —
//! validated byte-exact against RFC 8032 §7.4/§7.5's official vectors in
//! `kat_test.zig`. `Point.mul` is a constant-time 4-bit fixed-window
//! scalar mult (16-entry table + masked table scan), used by both key
//! generation and signing; `verify`'s point work uses a variable-time
//! Straus double-scalar mult (public inputs only).
//!
//! Zig std GAP: yes — `std.crypto.sign.Ed25519` supplies the identical
//! SHAPE of API for Ed25519 (`KeyPair`/`Signature`/sign/verify, SHA-512,
//! the empty `dom2` for pure Ed25519); this module is the same shape over
//! edwards448 / SHAKE256 / the non-empty `dom4` RFC 8032 §5.1 mandates
//! for Ed448 (Ed25519's `dom2` is only non-empty for the `Ed25519ctx`/
//! `Ed25519ph` variants `std.crypto.sign.Ed25519` does not implement —
//! Ed448 has no "plain, no context" variant at all, `dom4` always
//! applies).

const std = @import("std");
const field = @import("field.zig");
const scalar = @import("scalar.zig");
const Fe = field.Fe;
const Shake256 = std.crypto.hash.sha3.Shake256;

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "RFC 8032 (EdDSA), §5.2 Ed448/Ed448ph specifically — same API shape as std.crypto.sign.Ed25519 one curve family up (SHAKE256 in place of SHA-512, the mandatory non-empty dom4 domain prefix in place of Ed25519's optional dom2); this module's field.zig/scalar.zig supply the Fp448 base field and mod-L scalar field std.crypto.ecc.Edwards25519/.scalar supply for the 25519 case",
    .deps = .{},
};

/// `d = -39081 (mod p)` — edwards448's curve constant (RFC 8032 §5.2
/// Table 2: "d of edwards448 in [RFC7748] (i.e., -39081)"). A canonical
/// `Fe`, computed once at comptime via `Fe.fromBytes` (REAL — no field
/// arithmetic needed to construct this constant, only byte parsing).
/// UNRELATED IN SIGN to `x448.zig`'s `a24 = 39081` despite the numeric
/// coincidence — see that module's own doc comment on `a24`.
pub const d: Fe = Fe.fromBytes(hexBytes(field.encoded_bytes, "5667fffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff")) catch
    @compileError("ed448: malformed d constant bytes");

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// A point on edwards448, in projective `(X, Y, Z)` coordinates
/// (`x = X/Z`, `y = Y/Z`) — RFC 8032 §5.2.4's own representation. No `T`
/// extended coordinate is needed (unlike `std.crypto.ecc.Edwards25519`'s
/// `x`/`y`/`z`/`t`): edwards448 is UNTWISTED (`a = 1`), and `d` is a
/// quadratic NON-residue mod `p` (the property that makes the curve
/// "complete" without the twisted/extended-coordinates trick 25519 needs
/// for its `a = -1` curve — RFC 8032 §5.2.4 gives the plain 3-coordinate
/// formulas directly for exactly this reason).
pub const Point = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    /// The neutral element `(0, 1)`, i.e. projective `(0, Z, Z)` for any
    /// nonzero `Z` — here `Z = 1`.
    pub const identityElement: Point = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.one };

    /// The edwards448 base point `B` (RFC 8032 §5.2 Table 2's `X(P)`/
    /// `Y(P)`), `Z = 1`. Constructed via `Fe.fromBytes` at comptime —
    /// REAL (byte parsing only); independently confirmed to satisfy the
    /// untwisted curve equation `x^2 + y^2 = 1 + d*x^2*y^2` at scaffold
    /// time (see `NOTICE`'s "Verification performed" section) and
    /// re-checked at runtime by the "base point satisfies the curve
    /// equation" test below.
    pub const basePoint: Point = .{
        .x = Fe.fromBytes(hexBytes(field.encoded_bytes, "5ec00cc72ba826268e93008be1803b431165b62af71aae1264a4d3a324e36dea67170f477065149eda36bf22a6151d22ed0ded6bc670194f")) catch
            @compileError("ed448: malformed base point x"),
        .y = Fe.fromBytes(hexBytes(field.encoded_bytes, "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f69")) catch
            @compileError("ed448: malformed base point y"),
        .z = Fe.one,
    };

    /// Point addition (RFC 8032 §5.2.4's complete-addition formulas for
    /// the untwisted `a = 1` case — valid for ANY pair of valid input
    /// points, no exceptional cases):
    ///
    /// ```text
    /// A = Z1*Z2;  B = A^2;  C = X1*X2;  D = Y1*Y2
    /// E = d*C*D;  F = B - E;  G = B + E
    /// H = (X1+Y1) * (X2+Y2)
    /// X3 = A*F*(H - C - D)
    /// Y3 = A*G*(D - C)
    /// Z3 = F*G
    /// ```
    pub fn add(p: Point, q: Point) Point {
        const a = p.z.mul(q.z);
        const b = a.square();
        const c = p.x.mul(q.x);
        const dd = p.y.mul(q.y); // "D" (module-level `d` is the curve constant)
        const e = d.mul(c).mul(dd);
        const f = b.sub(e);
        const g = b.add(e);
        const h = p.x.add(p.y).mul(q.x.add(q.y));
        return .{
            .x = a.mul(f).mul(h.sub(c).sub(dd)),
            .y = a.mul(g).mul(dd.sub(c)),
            .z = f.mul(g),
        };
    }

    /// Point doubling (RFC 8032 §5.2.4's dedicated doubling formula,
    /// cheaper than `add(p, p)` — saves multiple multiplications by
    /// turning cross-products into squares):
    ///
    /// ```text
    /// B = (X1+Y1)^2;  C = X1^2;  D = Y1^2
    /// E = C + D;  H = Z1^2;  J = E - 2*H
    /// X3 = (B-E)*J
    /// Y3 = E*(C-D)
    /// Z3 = E*J
    /// ```
    pub fn dbl(p: Point) Point {
        const b = p.x.add(p.y).square();
        const c = p.x.square();
        const dd = p.y.square(); // "D" (module-level `d` is the curve constant)
        const e = c.add(dd);
        const h = p.z.square();
        const j = e.sub(h).sub(h);
        return .{
            .x = b.sub(e).mul(j),
            .y = e.mul(c.sub(dd)),
            .z = e.mul(j),
        };
    }

    /// `-p` — flips the sign of the `X` coordinate (`(-x, y)` is always
    /// the negation of `(x, y)` on an Edwards curve, same identity
    /// `std.crypto.ecc.Edwards25519.neg` uses).
    pub fn neg(p: Point) Point {
        return .{ .x = p.x.neg(), .y = p.y, .z = p.z };
    }

    /// Constant-time componentwise select: returns `a` if `cond`, else
    /// `b`. REAL — delegates entirely to `field.zig`'s already-REAL
    /// `Fe.ctSelect`, so `mul`'s constant-time double-and-add skeleton
    /// below can call this even before `Fe`'s own arithmetic lands.
    pub fn ctSelect(cond: bool, a: Point, b: Point) Point {
        return .{
            .x = Fe.ctSelect(cond, a.x, b.x),
            .y = Fe.ctSelect(cond, a.y, b.y),
            .z = Fe.ctSelect(cond, a.z, b.z),
        };
    }

    /// Scalar multiplication `[s]p`, `s` a 57-byte little-endian scalar.
    /// Covers bits 447 downto 0 — NOT merely `L`'s 446 significant bits:
    /// RFC 8032 §5.2.5's CLAMPED secret scalar (`scalar.clamp` sets bit
    /// 447, the high bit of byte 55) is deliberately used UN-reduced by
    /// key generation and signing, so bit 447 must participate.
    /// Canonical (`< L`) scalars from `reduceWide`/`Signature.s` simply
    /// have that bit zero. Construction: constant-time left-to-right
    /// double-and-add, using `ctSelect` to make the conditional "add or
    /// don't" branchless — the point addition is computed
    /// unconditionally every iteration and mask-selected in or out; the
    /// loop has a fixed 448 iterations regardless of `s`'s value:
    ///
    /// ```text
    /// acc = identityElement
    /// for t = 447 downto 0:
    ///     acc = acc.dbl()
    ///     bit_t = (s >> t) & 1
    ///     acc = ctSelect(bit_t == 1, acc.add(p), acc)
    /// return acc
    /// ```
    ///
    /// Constant-time. Uses a fixed 4-bit window (mirroring
    /// `std.crypto.ecc.Edwards25519.mul`'s `pcMul16` precomputed-window
    /// pattern): a 16-entry table `[0]p..[15]p` is built once, then the
    /// 448-bit scalar is consumed four bits at a time (112 windows), each
    /// window contributing four doublings and one table lookup. Cuts the
    /// point ADDITIONS from 448 (one per bit) to ~112 + 15 (table build)
    /// while keeping the doubling count identical, and the complete
    /// Edwards addition formula makes the `nibble == 0` case (add the
    /// identity table entry) exceptional-case-free.
    ///
    /// SECRET-SCALAR CONSTANT TIME: the window nibble indexes the table
    /// via a MASKED SCAN (`ctSelectPoint` touches all 16 entries and
    /// mask-selects — never a secret-dependent load or branch), and
    /// `Fe.ctSelect` under it is a pure limb-mask merge. The table is
    /// built from `p` (public: base point for sign/keygen; the input
    /// element for decaf448) and only the SCALAR is secret, so building
    /// the table is data-independent regardless.
    pub fn mul(p: Point, s: scalar.CompressedScalar) Point {
        var table: [16]Point = undefined;
        table[0] = identityElement;
        table[1] = p;
        inline for (2..16) |j| table[j] = table[j - 1].add(p);

        var acc = identityElement;
        var w: usize = 112; // 112 nibbles = 448 bits (bit 447 downto 0)
        while (w > 0) {
            w -= 1;
            acc = acc.dbl().dbl().dbl().dbl();
            const shift = w * 4;
            const nibble: u4 = @truncate(s[shift / 8] >> @intCast(shift % 8));
            acc = acc.add(ctSelectPoint(&table, nibble));
        }
        return acc;
    }

    /// Constant-time lookup of `table[idx]` for a SECRET `idx`: scans all
    /// 16 entries, mask-selecting the one whose (compile-time) position
    /// equals `idx`. No secret-dependent memory index or branch — the only
    /// data-dependent value is the boolean fed to the branch-free
    /// `Fe.ctSelect` limb merge. `table[0]` is the identity, so an `idx`
    /// of 0 correctly yields the neutral element.
    fn ctSelectPoint(table: *const [16]Point, idx: u4) Point {
        var r = identityElement;
        inline for (0..16) |j| {
            r = ctSelect(@as(u4, @intCast(j)) == idx, table[j], r);
        }
        return r;
    }

    /// Fixed-base comb table for the base point `B`:
    /// `baseComb[w][d] = [d * 2^(4w)] * B` (`w` in `0..112`, `d` in
    /// `0..15`), precomputed at COMPTIME. This is the "bigger win"
    /// fixed-base variant of the windowed method: because every window's
    /// multiples of `B` are already baked in, `mulBasePoint` needs ZERO
    /// runtime doublings — just 112 masked table lookups + adds — where
    /// the generic `mul` still pays 448 doublings. Sign and key generation
    /// (both `[s]B`) get this; variable-base callers (decaf448, verify's
    /// `[k]A'`) keep the generic `mul`/Straus path. `[w][0]` is the
    /// identity so a zero nibble contributes nothing.
    const baseComb: [112][16]Point = blk: {
        @setEvalBranchQuota(50_000_000);
        var tbl: [112][16]Point = undefined;
        var base = basePoint;
        for (0..112) |w| {
            tbl[w][0] = identityElement;
            tbl[w][1] = base;
            for (2..16) |di| tbl[w][di] = tbl[w][di - 1].add(base);
            // Advance the base by one 4-bit window: base *= 2^4.
            base = base.dbl().dbl().dbl().dbl();
        }
        break :blk tbl;
    };

    /// Constant-time `[s]B` via the fixed-base comb (`baseComb`) — no
    /// runtime doublings, 112 masked lookups + adds. Same CT discipline as
    /// `mul`: the secret nibble drives a masked scan (`ctSelectPoint`),
    /// never a secret-dependent load or branch. Used by `KeyPair.create`
    /// and `signInternal` for their `[s]B` / `[r]B` base-point mults.
    pub fn mulBasePoint(s: scalar.CompressedScalar) Point {
        var acc = identityElement;
        inline for (0..112) |w| {
            const shift = w * 4;
            const nibble: u4 = @truncate(s[shift / 8] >> @intCast(shift % 8));
            acc = acc.add(ctSelectPoint(&baseComb[w], nibble));
        }
        return acc;
    }

    /// Variable-time `[s1]p1 + [s2]p2`, for PUBLIC inputs only (Ed448
    /// `verify`). Straus/Shamir simultaneous double-scalar multiplication
    /// with a shared 4-bit window: one interleaved 448-doubling pass over
    /// both scalars, with a direct (data-dependent) table index and a
    /// skipped add on a zero nibble — legitimate here because every input
    /// to verification (`S`, `k`, `B`, `A'`) is public. Replaces the two
    /// full constant-time `Point.mul`s the cofactored check used to run
    /// (~half the doublings, plus no masked-scan overhead), the source of
    /// verify's outsized gap vs C (audit F2).
    fn mulDoubleVartime(s1: scalar.CompressedScalar, p1: Point, s2: scalar.CompressedScalar, p2: Point) Point {
        var t1: [16]Point = undefined;
        var t2: [16]Point = undefined;
        t1[0] = identityElement;
        t2[0] = identityElement;
        t1[1] = p1;
        t2[1] = p2;
        inline for (2..16) |j| {
            t1[j] = t1[j - 1].add(p1);
            t2[j] = t2[j - 1].add(p2);
        }
        var acc = identityElement;
        var w: usize = 112;
        while (w > 0) {
            w -= 1;
            acc = acc.dbl().dbl().dbl().dbl();
            const shift = w * 4;
            const n1: u4 = @truncate(s1[shift / 8] >> @intCast(shift % 8));
            const n2: u4 = @truncate(s2[shift / 8] >> @intCast(shift % 8));
            if (n1 != 0) acc = acc.add(t1[n1]);
            if (n2 != 0) acc = acc.add(t2[n2]);
        }
        return acc;
    }

    /// Encode a point per RFC 8032 §5.2.2: convert to affine
    /// (`x = X*Z^-1`, `y = Y*Z^-1`), write `y` as little-endian 57 bytes
    /// (top byte always `0`), then copy `x`'s parity bit
    /// (`Fe.isOdd`) into the top bit of that final byte.
    pub fn toBytes(p: Point) [57]u8 {
        const z_inv = p.z.invert() catch unreachable; // z is never 0 for a valid point
        const x_affine = p.x.mul(z_inv);
        const y_affine = p.y.mul(z_inv);
        var out = [_]u8{0} ** 57;
        out[0..field.encoded_bytes].* = y_affine.toBytes();
        if (x_affine.isOdd()) out[56] |= 0x80;
        return out;
    }

    pub const DecodeError = error{ NonCanonical, InvalidEncoding };

    /// Decode a point per RFC 8032 §5.2.3:
    ///
    /// 1. Interpret the 57 bytes little-endian; bit 455 (the top bit of
    ///    byte 56) is `x_0`, the sign bit. Clear it to recover `y`; if
    ///    `y >= p`, fail (`Fe.fromBytes`'s own canonical check —
    ///    `error.NonCanonical`).
    /// 2. `u = y^2 - 1`, `v = d*y^2 - 1` (the denominator `v` is never
    ///    zero mod `p` for a valid curve — RFC 8032's own claim).
    /// 3. Candidate `x = sqrt(u * v^-1)` (`Fe.sqrt`, which already
    ///    verifies `candidate^2 == u/v` internally and returns `null` on
    ///    mismatch — see `field.zig`'s `Fe.sqrt` doc comment; this is a
    ///    correctness-equivalent, simpler restatement of RFC 8032's own
    ///    combined-power trick `x = u^3*v*(u^5*v^3)^((p-3)/4)`, which
    ///    exists purely as a performance optimization fusing the
    ///    inversion and square-root into one exponentiation — NOT a
    ///    different mathematical result). `null` => `error.
    ///    InvalidEncoding` (no square root exists, `y` is not a valid
    ///    curve point's y-coordinate).
    /// 4. If `x == 0` and `x_0 == 1`, fail (`error.InvalidEncoding` — RFC
    ///    8032's explicit exceptional case: `x=0` has no "negative"
    ///    representative, so `x_0 = 1` can never legitimately encode it).
    ///    Otherwise, if `x`'s parity != `x_0`, negate `x` (`p - x`).
    /// 5. Return `Point{ .x = x, .y = y, .z = Fe.one }`.
    pub fn fromBytes(bytes: [57]u8) DecodeError!Point {
        const x0: u1 = @intCast(bytes[56] >> 7);
        // y occupies bytes 0..55 IN FULL (p < 2^448 means bits 448+ are
        // out of range, and those live in byte 56 — byte 55's top bit,
        // bit 447, is a legitimate part of y; a canonical y >= 2^447
        // exists whenever y > p/2... i.e. for about half of all points).
        // The sign bit x0 is byte 56's top bit; byte 56's remaining 7
        // bits (448..454) must be zero.
        const y_bytes: [field.encoded_bytes]u8 = bytes[0..field.encoded_bytes].*;
        if (bytes[56] & 0x7f != 0) return error.InvalidEncoding; // bits 448..454 must be zero
        const y = Fe.fromBytes(y_bytes) catch return error.NonCanonical;

        const y2 = y.mul(y);
        const u = y2.sub(Fe.one);
        const v = d.mul(y2).sub(Fe.one);
        const v_inv = v.invert() catch unreachable; // v is never 0 for edwards448 (RFC 8032 5.2.3)
        var x = Fe.sqrt(u.mul(v_inv)) orelse return error.InvalidEncoding;

        if (x.isZero() and x0 == 1) return error.InvalidEncoding;
        if (@intFromBool(x.isOdd()) != x0) x = x.neg();

        return .{ .x = x, .y = y, .z = Fe.one };
    }

    /// Multiply `p` by edwards448's cofactor (4) — two doublings. Used by
    /// `verify`'s cofactored group-equation check (RFC 8032 §5.2.7 step 3:
    /// `[4][S]B = [4]R + [4][k]A'`).
    pub fn clearCofactor(p: Point) Point {
        return p.dbl().dbl();
    }

    /// `true` iff `p` and `q` represent the same affine point, WITHOUT
    /// requiring either to be normalized (`Z = 1`) first — the standard
    /// projective-coordinates equivalence check `x1/z1 == x2/z2 && y1/z1
    /// == y2/z2`, cross-multiplied to avoid two inversions:
    /// `X1*Z2 == X2*Z1 && Y1*Z2 == Y2*Z1`. Used by `verify`'s final
    /// group-equation comparison instead of `toBytes`-then-compare, so a
    /// crypto-core pass need not implement `Fe.invert` before `verify`'s
    /// OWN comparison step can be exercised (though `Point.fromBytes`
    /// inside `verifyInternal` still needs it to decode `R`/`A'` in the
    /// first place).
    pub fn equivalent(p: Point, q: Point) bool {
        const x_ok = p.x.mul(q.z).eql(q.x.mul(p.z));
        const y_ok = p.y.mul(q.z).eql(q.y.mul(p.z));
        return x_ok and y_ok;
    }
};

// ── dom4 domain-separation framing (REAL) ──────────────────────────────

/// Maximum context length RFC 8032 §5.1 permits (`octet(OLEN(y))` — a
/// single length byte, so `y` is at most 255 octets).
pub const max_context_length = 255;

pub const ContextError = error{ContextTooLong};

/// Absorb RFC 8032's `dom4(x, y)` prefix into a SHAKE256 hasher:
/// `"SigEd448" || octet(phflag) || octet(len(ctx)) || ctx` (RFC 8032
/// §5.1's definition, specialized to Ed448's 8-byte ASCII tag — DISTINCT
/// from Ed25519's 32-byte `"SigEd25519 no Ed25519 collisions"` `dom2`
/// tag). REAL: pure byte framing, no hashing math of its own beyond
/// calling the (real, std-provided) `Shake256.update`.
pub fn absorbDom4(hasher: *Shake256, phflag: u1, ctx: []const u8) ContextError!void {
    if (ctx.len > max_context_length) return error.ContextTooLong;
    hasher.update("SigEd448");
    hasher.update(&[_]u8{ phflag, @intCast(ctx.len) });
    hasher.update(ctx);
}

/// `SHAKE256(dom4(phflag, ctx) || parts..., 114)` — the shared digest
/// shape every one of RFC 8032 §5.2.5/§5.2.6/§5.2.7's SHAKE256 calls
/// uses (differing only in what `parts` are absorbed after `dom4`). REAL:
/// pure hashing/framing, no field/scalar arithmetic.
fn shake114(phflag: u1, ctx: []const u8, parts: []const []const u8) ContextError![114]u8 {
    var hasher = Shake256.init(.{});
    try absorbDom4(&hasher, phflag, ctx);
    for (parts) |part| hasher.update(part);
    var out: [114]u8 = undefined;
    hasher.squeeze(&out);
    return out;
}

// ── keys / signatures ───────────────────────────────────────────────────

pub const SecretKey = struct {
    /// 57 octets of cryptographically secure random data (RFC 8032
    /// §5.2.5) — this IS the seed, unlike `std.crypto.sign.Ed25519.
    /// SecretKey` (which stores seed‖pubkey together); Ed448's public key
    /// is always re-derived from this seed, never stored alongside it.
    bytes: [57]u8,

    pub fn fromBytes(bytes: [57]u8) SecretKey {
        return .{ .bytes = bytes };
    }
    pub fn toBytes(sk: SecretKey) [57]u8 {
        return sk.bytes;
    }

    /// Zeroize the 57-byte seed in place. Idempotent (re-zeroing an
    /// already-zero buffer is a no-op). Callers that hold a `SecretKey`
    /// past its useful lifetime should call this before letting it go
    /// out of scope — hygiene only, no effect on any crypto result.
    pub fn deinit(self: *SecretKey) void {
        std.crypto.secureZero(u8, &self.bytes);
    }
};

pub const PublicKey = struct {
    bytes: [57]u8,

    pub fn fromBytes(bytes: [57]u8) PublicKey {
        return .{ .bytes = bytes };
    }
    pub fn toBytes(pk: PublicKey) [57]u8 {
        return pk.bytes;
    }
    /// Decode into a curve `Point` — see `Point.fromBytes`.
    pub fn lift(pk: PublicKey) Point.DecodeError!Point {
        return Point.fromBytes(pk.bytes);
    }
};

pub const Signature = struct {
    /// The encoded nonce-commitment POINT `R` (57 bytes) — NOT a scalar,
    /// unlike Ed25519's `r` field, which is x-only (`std.crypto.ecc.
    /// Edwards25519`'s 32-byte compressed-point encoding already IS a
    /// full point encoding for that curve too, so this is actually the
    /// same shape as Ed25519's `r` — both are compressed POINTS; noted
    /// here only because Ed448's wider 57-byte width makes the point vs.
    /// scalar distinction easy to blur when skimming byte counts).
    r: [57]u8,
    /// The scalar `S` (57 bytes, `< L`).
    s: [57]u8,

    pub const encoded_length = 114;

    pub fn toBytes(sig: Signature) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        out[0..57].* = sig.r;
        out[57..114].* = sig.s;
        return out;
    }

    pub const FromBytesError = error{NonCanonical};

    /// REAL: pure byte split, plus `scalar.rejectNonCanonical` on `S`
    /// (RFC 8032 §5.2.7 step 1: "Decode ... the second half as an
    /// integer S, in the range 0 <= s < L. ... If any of the decodings
    /// fail (including S being out of range), the signature is
    /// invalid."). `R`'s canonical-ness is checked lazily, by `Point.
    /// fromBytes`, at `verify` time — not here (mirrors `bip340.
    /// Signature.fromBytes`'s own split between eager range checks and
    /// lazy point-decode checks).
    pub fn fromBytes(bytes: [encoded_length]u8) FromBytesError!Signature {
        const s = bytes[57..114].*;
        try scalar.rejectNonCanonical(s);
        return .{ .r = bytes[0..57].*, .s = s };
    }
};

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    /// RFC 8032 §5.2.5's key generation:
    ///
    /// 1. `h = SHAKE256(seed, 114)`.
    /// 2. `s = clamp(h[0..57])` (`scalar.clamp`).
    /// 3. `A = [s]B` (constant-time `Point.mul` on `Point.basePoint`;
    ///    the clamped `s` is used UN-reduced, bit 447 set — see
    ///    `Point.mul`'s doc comment).
    /// 4. Public key = `A.toBytes()`.
    pub fn create(seed: [57]u8) KeyPair {
        var h: [114]u8 = undefined;
        defer std.crypto.secureZero(u8, &h);
        Shake256.hash(&seed, &h, .{});
        var s = h[0..57].*;
        defer std.crypto.secureZero(u8, &s);
        scalar.clamp(&s);
        const a_point = Point.mulBasePoint(s);
        return .{
            .public_key = PublicKey.fromBytes(a_point.toBytes()),
            .secret_key = SecretKey.fromBytes(seed),
        };
    }

    /// Generate a new, random key pair.
    pub fn generate(io: std.Io) KeyPair {
        var seed: [57]u8 = undefined;
        io.random(&seed);
        return create(seed);
    }

    /// Zeroize `secret_key` in place; `public_key` is left untouched (it
    /// is not secret). Idempotent. Hygiene only — no effect on any
    /// signature produced before the call.
    pub fn deinit(self: *KeyPair) void {
        self.secret_key.deinit();
    }
};

pub const SignError = ContextError;

/// Shared RFC 8032 §5.2.6 sign construction for both Ed448 (`phflag=0`,
/// `ph_message = message` unchanged) and Ed448ph (`phflag=1`,
/// `ph_message = SHAKE256(message, 64)` — the caller-side prehash;
/// `signPh` below does that prehash before calling in):
///
/// 1. `h = SHAKE256(secret_key.bytes, 114)`; `s = clamp(h[0..57])`
///    (secret scalar); `prefix = h[57..114]`.
/// 2. `r = SHAKE256(dom4(phflag,ctx) || prefix || ph_message, 114) mod L`
///    (`scalar.reduceWide`).
/// 3. `R = [r]B`; encode as `r_bytes` (57 bytes).
/// 4. `k = SHAKE256(dom4(phflag,ctx) || r_bytes || A || ph_message, 114)
///    mod L`.
/// 5. `S = (r + k*s) mod L` (`scalar.mulAdd`).
/// 6. `signature = r_bytes || bytes(S)`.
fn signInternal(kp: KeyPair, ph_message: []const u8, ctx: []const u8, phflag: u1) SignError!Signature {
    var h: [114]u8 = undefined;
    defer std.crypto.secureZero(u8, &h);
    Shake256.hash(&kp.secret_key.bytes, &h, .{});
    var s = h[0..57].*;
    defer std.crypto.secureZero(u8, &s);
    scalar.clamp(&s);
    const prefix = h[57..114];

    var r_digest = try shake114(phflag, ctx, &.{ prefix, ph_message });
    defer std.crypto.secureZero(u8, &r_digest);
    var r_scalar = scalar.reduceWide(r_digest);
    defer std.crypto.secureZero(u8, &r_scalar);
    const r_point = Point.mulBasePoint(r_scalar);
    const r_bytes = r_point.toBytes();

    const k_digest = try shake114(phflag, ctx, &.{ &r_bytes, &kp.public_key.bytes, ph_message });
    const k_scalar = scalar.reduceWide(k_digest);

    const s_scalar = scalar.mulAdd(k_scalar, s, r_scalar);
    return .{ .r = r_bytes, .s = s_scalar };
}

/// Ed448 (`phflag = 0`, `PH` = identity — RFC 8032 §5.2 Table 2).
pub fn sign(kp: KeyPair, msg: []const u8, ctx: []const u8) SignError!Signature {
    return signInternal(kp, msg, ctx, 0);
}

/// Ed448ph (`phflag = 1`, `PH(x) = SHAKE256(x, 64)` — RFC 8032 §5.2's
/// "Ed448ph is the same but with PH being SHAKE256(x, 64) and phflag
/// being 1"). REAL: the prehash itself is a plain SHAKE256 call, no
/// curve/scalar math.
pub fn signPh(kp: KeyPair, msg: []const u8, ctx: []const u8) SignError!Signature {
    var ph: [64]u8 = undefined;
    Shake256.hash(msg, &ph, .{});
    return signInternal(kp, &ph, ctx, 1);
}

pub const VerifyError = ContextError || Point.DecodeError || error{ InvalidScalar, SignatureVerificationFailed };

/// Shared RFC 8032 §5.2.7 verify construction (variable-time is
/// acceptable throughout — every input to verification is public):
///
/// 1. Decode `sig.r` as `R` (`Point.fromBytes`), `sig.s` as `S` (already
///    range-checked by `Signature.fromBytes` — re-derived here from the
///    struct fields directly, no re-parse needed), `pubkey.bytes` as
///    `A'` (`Point.fromBytes`). Any decode failure => invalid signature.
/// 2. `k = SHAKE256(dom4(phflag,ctx) || sig.r || pubkey || ph_message,
///    114) mod L` — IDENTICAL computation to `signInternal`'s step 4.
/// 3. Accept iff `[4][S]B == [4]R + [4][k]A'` (the COFACTORED check RFC
///    8032 explicitly permits: "It's sufficient, but not required, to
///    instead check [S]B = R + [k]A'" — this module uses the cofactored
///    form, matching `std.crypto.sign.Ed25519`'s own default `verify`
///    method's cofactored-verification choice for the analogous 25519
///    case; see `../SPEC.md`'s threat-model note on why).
fn verifyInternal(sig: Signature, ph_message: []const u8, ctx: []const u8, pubkey: PublicKey, phflag: u1) VerifyError!void {
    const r_point = try Point.fromBytes(sig.r);
    const a_point = try Point.fromBytes(pubkey.bytes);

    const k_digest = try shake114(phflag, ctx, &.{ &sig.r, &pubkey.bytes, ph_message });
    const k_scalar = scalar.reduceWide(k_digest);

    // Cofactored check `[4][S]B == [4]R + [4][k]A'`, rearranged to
    // `[4]([S]B + [k](-A')) == [4]R` so both scalar mults fold into ONE
    // vartime Straus double-scalar pass (public inputs — see
    // `mulDoubleVartime`).
    const lhs = Point.mulDoubleVartime(sig.s, Point.basePoint, k_scalar, a_point.neg()).clearCofactor();

    if (!lhs.equivalent(r_point.clearCofactor())) return error.SignatureVerificationFailed;
}

/// Ed448 verify (`phflag = 0`).
pub fn verify(sig: Signature, msg: []const u8, ctx: []const u8, pubkey: PublicKey) VerifyError!void {
    return verifyInternal(sig, msg, ctx, pubkey, 0);
}

/// Ed448ph verify (`phflag = 1`) — REAL prehash, same as `signPh`.
pub fn verifyPh(sig: Signature, msg: []const u8, ctx: []const u8, pubkey: PublicKey) VerifyError!void {
    var ph: [64]u8 = undefined;
    Shake256.hash(msg, &ph, .{});
    return verifyInternal(sig, &ph, ctx, pubkey, 1);
}

// ── tests ────────────────────────────────────────────────────────────────

test "meta.model_after names RFC 8032 / Ed448" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "8032") != null);
}

test "Signature.encoded_length == 114 (57 + 57, RFC 8032 §5.2)" {
    try std.testing.expectEqual(@as(usize, 114), Signature.encoded_length);
}

test "Signature round-trips through fromBytes/toBytes (REAL codec, no crypto core)" {
    var bytes: [114]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @intCast((i * 7 + 3) % 251);
    bytes[113] = 0x00; // keep S canonical (< L): clear the reserved-zero high byte
    bytes[112] &= 0x3f; // and the next byte, per L's own top-bits-zero shape
    const sig = try Signature.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &sig.toBytes());
}

test "Signature.fromBytes rejects a non-canonical S (>= L)" {
    var bytes = [_]u8{0} ** 114;
    bytes[57..114].* = scalar.l_bytes; // S == L itself: non-canonical
    try std.testing.expectError(error.NonCanonical, Signature.fromBytes(bytes));
}

test "absorbDom4 rejects an oversized context (REAL)" {
    var hasher = Shake256.init(.{});
    const too_long = [_]u8{0} ** 256;
    try std.testing.expectError(error.ContextTooLong, absorbDom4(&hasher, 0, &too_long));
}

test "absorbDom4 produces the RFC 8032 §5.1 dom4 byte layout (REAL, checked against a fixed digest)" {
    // dom4(0, "foo") = "SigEd448" || 0x00 || 0x03 || "foo" -- 12 bytes.
    // Cross-checked by hashing the same 12 bytes directly with
    // Shake256.hash and comparing digests, independent of absorbDom4's
    // own internals.
    var hasher = Shake256.init(.{});
    try absorbDom4(&hasher, 0, "foo");
    var got: [32]u8 = undefined;
    hasher.squeeze(&got);

    var want_hasher = Shake256.init(.{});
    want_hasher.update("SigEd448" ++ [_]u8{ 0, 3 } ++ "foo");
    var want: [32]u8 = undefined;
    want_hasher.squeeze(&want);

    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "base point satisfies the curve equation x^2 + y^2 == 1 + d*x^2*y^2" {
    const x2 = Point.basePoint.x.square();
    const y2 = Point.basePoint.y.square();
    const lhs = x2.add(y2);
    const rhs = Fe.one.add(d.mul(x2).mul(y2));
    try std.testing.expect(lhs.eql(rhs));
}

test "Point encode/decode round-trip: base point, its double, and its negation (odd/even x, high/low y)" {
    const points = [_]Point{
        Point.basePoint,
        Point.basePoint.dbl(),
        Point.basePoint.neg(),
        Point.basePoint.dbl().add(Point.basePoint),
    };
    for (points) |p| {
        const enc = p.toBytes();
        const dec = try Point.fromBytes(enc);
        try std.testing.expect(dec.equivalent(p));
        try std.testing.expectEqualSlices(u8, &enc, &dec.toBytes());
    }
    // Identity: (0, 1), sign bit clear.
    var id_enc = [_]u8{0} ** 57;
    id_enc[0] = 1;
    try std.testing.expectEqualSlices(u8, &id_enc, &Point.identityElement.toBytes());
    try std.testing.expect((try Point.fromBytes(id_enc)).equivalent(Point.identityElement));
}

test "Point.fromBytes rejects non-canonical and invalid encodings" {
    // y == p (non-canonical field element), sign bit clear.
    var p_enc = [_]u8{0} ** 57;
    p_enc[0..field.encoded_bytes].* = field.p_bytes;
    try std.testing.expectError(error.NonCanonical, Point.fromBytes(p_enc));

    // Nonzero padding bits in byte 56 (bits 448..454 must be zero).
    var pad_enc = Point.basePoint.toBytes();
    pad_enc[56] |= 0x01;
    try std.testing.expectError(error.InvalidEncoding, Point.fromBytes(pad_enc));

    // x == 0 with sign bit set: the identity's "negative" does not exist.
    var neg_id = [_]u8{0} ** 57;
    neg_id[0] = 1;
    neg_id[56] = 0x80;
    try std.testing.expectError(error.InvalidEncoding, Point.fromBytes(neg_id));

    // y == 2 is not on the curve (u/v is a non-residue for it).
    var off_curve = [_]u8{0} ** 57;
    off_curve[0] = 2;
    try std.testing.expectError(error.InvalidEncoding, Point.fromBytes(off_curve));
}

test "RFC 8032 §7.4 Ed448 test vector (empty message): keygen public key, byte-exact" {
    // kat_test.zig carries the full RFC 8032 §7.4/§7.5 vector set
    // (including the signature bytes and verify/tamper checks); this
    // file's own smoke test checks the derived public key and that a
    // produced signature round-trips through verify.
    var seed: [57]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "6c82a562cb808d10d632be89c8513ebf" ++
        "6c929f34ddfa8c9f63c9960ef6e348a3" ++
        "528c8a3fcc2f044e39a3fc5b94492f8f" ++
        "032e7549a20098f95b");
    var expected_pk: [57]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_pk, "5fd7449b59b461fd2ce787ec616ad46a" ++
        "1da1342485a70e1f8a0ea75d80e96778" ++
        "edf124769b46c7061bd6783df1e50f6c" ++
        "d1fa1abeafe8256180");
    const kp = KeyPair.create(seed);
    try std.testing.expectEqualSlices(u8, &expected_pk, &kp.public_key.bytes);
    const sig = try sign(kp, "", "");
    try verify(sig, "", "", kp.public_key);
}

test "SecretKey.deinit zeroizes the 57-byte seed (regression: fails if secureZero is removed)" {
    var sk = SecretKey.fromBytes([_]u8{0xab} ** 57);
    sk.deinit();
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 57), &sk.bytes);
}

test "KeyPair.deinit zeroizes secret_key.bytes but leaves public_key untouched (regression)" {
    var seed: [57]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "6c82a562cb808d10d632be89c8513ebf" ++
        "6c929f34ddfa8c9f63c9960ef6e348a3" ++
        "528c8a3fcc2f044e39a3fc5b94492f8f" ++
        "032e7549a20098f95b");
    var kp = KeyPair.create(seed);
    const zero: [57]u8 = [_]u8{0} ** 57;
    try std.testing.expect(!std.mem.eql(u8, &kp.secret_key.bytes, &zero));
    kp.deinit();
    try std.testing.expectEqualSlices(u8, &zero, &kp.secret_key.bytes);
    try std.testing.expect(!std.mem.eql(u8, &kp.public_key.bytes, &zero));
}

// ── fuzz harnesses (untrusted-wire decoders) ────────────────────────────

test "fuzz: Point.fromBytes never crashes on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzPointFromBytes, .{});
}

fn fuzzPointFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [57]u8 = undefined;
    smith.bytes(&buf);
    const p = Point.fromBytes(buf) catch return;
    _ = p.toBytes();
    _ = p.clearCofactor();
}

test "fuzz: Signature.fromBytes never crashes on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzSignatureFromBytes, .{});
}

fn fuzzSignatureFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [Signature.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    const sig = Signature.fromBytes(buf) catch return;
    _ = sig.toBytes();
}
