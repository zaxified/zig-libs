// SPDX-License-Identifier: MIT

//! ecmult — VARIABLE-TIME `s1·G + s2·P` for PUBLIC scalars: the verifier's
//! `s·G − e·P` when one base is the generator (BIP340, ECDSA, adaptor).
//! libsecp256k1's `ecmult` design, re-derived on k256's `Fe`:
//!
//!   * **Jacobian coordinates** `(X, Y, Z)` ↦ `(X/Z², Y/Z³)` with the
//!     incomplete `a = 0` formulas — doubling 3M + 4S (libsecp256k1's
//!     `gej_double`), mixed addition 8M + 3S — where `group.zig`'s complete
//!     RCB law pays 6M + 2S and 12M. Incomplete means the special cases (identity, `a = ±b`) are
//!     branches; that is fine here and ONLY here, because every input is
//!     public. Secret scalars never reach this file (`group.mul` and
//!     `combMulBase` stay on RCB).
//!   * **GLV + wNAF** on both scalars: four half-length digit strings over one
//!     shared doubling chain (~129 doublings).
//!   * **P's table "effectively affine"**: the odd multiples `(2i+1)·P` are
//!     built in Jacobian and then brought to ONE common `Z` (z-ratio
//!     bookkeeping, no inversion). Under the curve isomorphism
//!     `(x, y) ↦ (Z²·x, Z³·y)` they are affine points, so every P addition is
//!     a mixed addition; the accumulator lives on the isomorphic curve and the
//!     common `Z` is multiplied back into its `Z` at the end. (`a = 0`, so the
//!     formulas never see the curve constant that the isomorphism changes.)
//!   * **Weak field elements** (`F`, since 2026-11-13): values `< 2^256`, not
//!     reduced below `p` between operations, so add/sub/mul skip the masked
//!     canonicalising select `Fe` pays (see `F`). Branch-free like `Fe`,
//!     but not a constant-time claim: public data only.
//!   * **G's table precomputed affine** at comptime with a wider window
//!     (`g_window`), together with `φ(G)`'s (`(β·x, y)`); its entries enter the
//!     isomorphic frame through the same common `Z` (`addGeScaled`).
//!
//! `group.Secp256k1.mulDoubleBasePublic` dispatches here when one base is
//! `basePoint` exactly, so every consumer gets it without an API change. The
//! RCB GLV path (`glvCombine`) and the plain double-and-add stay the oracles.

const std = @import("std");
const math = std.math;
const field = @import("field.zig");
const scalarmod = @import("scalar.zig");

const Fe = field.Fe;

// ── the weak field form (VARIABLE-TIME — public data only) ──────────────────
//
// `F` holds any value `< 2^256` congruent to the element, not necessarily
// `< p` — libsecp256k1's "magnitude" idea cut down to what four full limbs
// allow. `Fe`'s add/sub/mulSmall canonicalise after every operation (a second
// carry chain, a laundered mask and a 4-limb select each); here they only fold
// the carry/borrow out of 2^256 back in (`2^256 ≡ c`), one chain plus a masked
// constant, and the second fold that can follow (probability ~2^-220 on a real
// input: both operands within `c` of 2^256) is masked too. Every value here is
// public, but the code still does not branch on field values: a carry out of
// 2^256 is a coin flip a branch would mispredict, and callers such as
// `adaptor.preSign`'s self-check run this on values derived from a secret
// (published ones, but ctgrind counts them).
// `mul`/`sq` take and return weak values too (`field.mulWeak`: the two Solinas
// folds and a masked add of the final carry, instead of `Fe.mul`'s
// canonicalising four-limb select).
// Zero tests compare against both representatives, `0` and `p`.
// Measured 2026-11-13 (`zig build bench-bip340`): see SPEC § Performance.

const p_int: u256 = field.field_order;
const c_fold: u256 = (1 << 32) + 977; // 2^256 − p

/// `0 − bit` as a 256-bit mask, the bit laundered so LLVM keeps the masked
/// fold instead of a branch (a coin flip it would mispredict, or, for the rare
/// folds, a branch on data). No-op barrier at comptime.
inline fn mask(bit: u1) u256 {
    if (@inComptime()) return @as(u256, 0) -% bit;
    const b = asm (""
        : [ret] "=r" (-> u64),
        : [x] "0" (@as(u64, bit)),
    );
    return @as(u256, 0) -% @as(u256, b);
}

const F = struct {
    v: u256,

    const zero = F{ .v = 0 };
    const one = F{ .v = 1 };

    inline fn of(a: Fe) F {
        return .{ .v = a.toInt() };
    }

    /// The canonical element (one conditional subtract: `v < 2^256 < 2p`).
    inline fn fe(a: F) Fe {
        const d = @subWithOverflow(a.v, p_int); // borrow => a.v < p, keep it
        const r = d[0] +% (p_int & mask(d[1]));
        return .{ ._limbs = .{ @truncate(r), @truncate(r >> 64), @truncate(r >> 128), @truncate(r >> 192) } };
    }

    inline fn limbs(a: F) [4]u64 {
        return .{ @truncate(a.v), @truncate(a.v >> 64), @truncate(a.v >> 128), @truncate(a.v >> 192) };
    }

    inline fn ofLimbs(l: [4]u64) F {
        return .{ .v = @as(u256, l[0]) | (@as(u256, l[1]) << 64) | (@as(u256, l[2]) << 128) | (@as(u256, l[3]) << 192) };
    }

    inline fn mul(a: F, b: F) F {
        return ofLimbs(field.mulWeak(a.limbs(), b.limbs()));
    }

    inline fn sq(a: F) F {
        return ofLimbs(field.sqWeak(a.limbs()));
    }

    /// `a + b`: `s = a + b − k·2^256` (`k` the carry), `+ k·c`; a second
    /// carry leaves a value `< c`, so one more `+ c` cannot carry.
    inline fn add(a: F, b: F) F {
        const s = @addWithOverflow(a.v, b.v);
        const t = @addWithOverflow(s[0], c_fold & mask(s[1]));
        return .{ .v = t[0] +% (c_fold & mask(t[1])) };
    }

    inline fn dbl(a: F) F {
        return a.add(a);
    }

    /// `a − b`: a borrow means `a − b + 2^256`, so subtract `c`; a second
    /// borrow leaves a value `≥ 2^256 − c`, so one more `− c` cannot borrow.
    inline fn sub(a: F, b: F) F {
        const d = @subWithOverflow(a.v, b.v);
        const t = @subWithOverflow(d[0], c_fold & mask(d[1]));
        return .{ .v = t[0] -% (c_fold & mask(t[1])) };
    }

    inline fn neg(a: F) F {
        return zero.sub(a);
    }

    /// `k·a` for a small comptime `k`: `lo + hi·c` with `hi < k`, so
    /// `hi·c < 2^38` and a carry out of 2^256 leaves a value `< 2^38`.
    inline fn mulSmall(a: F, comptime k: u64) F {
        comptime std.debug.assert(k < 32);
        const w: u320 = @as(u320, a.v) * k;
        const hi: u256 = @intCast(w >> 256);
        const s = @addWithOverflow(@as(u256, @truncate(w)), hi * c_fold);
        return .{ .v = s[0] +% (c_fold & mask(s[1])) };
    }

    /// `a / 2`: `(a + p·(a odd)) >> 1`, with the 257th bit shifted back in.
    inline fn half(a: F) F {
        const s = @addWithOverflow(a.v, p_int & mask(@truncate(a.v & 1)));
        return .{ .v = (s[0] >> 1) | (@as(u256, s[1]) << 255) };
    }

    /// `v ∈ {0, p}` as ONE verdict: both limb-wise compares are folded into
    /// a single word before the test (two 256-bit `==` compiled to a chain
    /// of per-limb jumps — more ctgrind contexts on callers that feed this
    /// secret-derived values, such as `adaptor.preSign`'s self-check).
    inline fn isZero(a: F) bool {
        const l = a.limbs();
        const pl = comptime (F{ .v = p_int }).limbs();
        const z = l[0] | l[1] | l[2] | l[3];
        const zp = (l[0] ^ pl[0]) | (l[1] ^ pl[1]) | (l[2] ^ pl[2]) | (l[3] ^ pl[3]);
        // `x == 0` iff `(x | −x)` has its top bit clear.
        const nz = ((z | (0 -% z)) & (zp | (0 -% zp))) >> 63;
        return nz == 0;
    }
};

/// An affine point (public interface type; canonical coordinates). Never the
/// identity: tables hold odd multiples of a point of prime order.
pub const Ge = struct {
    x: Fe,
    y: Fe,
};

/// A Jacobian point (public interface type; canonical coordinates); `inf`
/// marks the identity (its coordinates are then meaningless).
pub const Gej = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    inf: bool,

    pub const infinity = Gej{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero, .inf = true };
};

/// `Ge` in the weak form.
const Gw = struct {
    x: F,
    y: F,

    inline fn of(a: Ge) Gw {
        return .{ .x = F.of(a.x), .y = F.of(a.y) };
    }

    fn neg(a: Gw) Gw {
        return .{ .x = a.x, .y = a.y.neg() };
    }
};

/// `Gej` in the weak form: what the multiply works on.
const Jw = struct {
    x: F,
    y: F,
    z: F,
    inf: bool,

    const infinity = Jw{ .x = F.zero, .y = F.one, .z = F.zero, .inf = true };

    fn of(a: Gej) Jw {
        return .{ .x = F.of(a.x), .y = F.of(a.y), .z = F.of(a.z), .inf = a.inf };
    }

    fn gej(a: Jw) Gej {
        return .{ .x = a.x.fe(), .y = a.y.fe(), .z = a.z.fe(), .inf = a.inf };
    }

    fn fromGe(a: Gw) Jw {
        return .{ .x = a.x, .y = a.y, .z = F.one, .inf = false };
    }

    /// `2a` for `a = 0`, libsecp256k1's `gej_double` (3M + 4S):
    /// `L = 3X²/2`, `S = Y²`, `T = X·S`, `X3 = L² − 2T`,
    /// `Y3 = L·(T − X3) − S²`, `Z3 = Y·Z` — dbl-2009-l's point with `Z` halved
    /// (so `X` quartered, `Y` divided by eight), which trades one square for a
    /// multiply and five of its eleven additions for one halving. Until
    /// 2026-11-13 this was dbl-2009-l itself (2M + 5S). secp256k1 has no point
    /// of order two (its order is an odd prime), so `Y = 0` never occurs.
    fn dbl(a: Jw) Jw {
        if (a.inf) return a;
        const s = a.y.sq();
        const l = a.x.sq().mulSmall(3).half();
        const t = a.x.mul(s);
        const x3 = l.sq().sub(t.dbl());
        const y3 = l.mul(t.sub(x3)).sub(s.sq());
        const z3 = a.y.mul(a.z);
        return .{ .x = x3, .y = y3, .z = z3, .inf = false };
    }

    /// `a + b` for `b` affine in `a`'s frame (mixed addition, 8M + 3S).
    fn addGe(a: Jw, b: Gw) Jw {
        if (a.inf) return fromGe(b);
        return addCore(a, b, a.z).p;
    }

    /// `a + ψ(b)` where `ψ(x, y) = (s²·x, s³·y)` maps the affine `b` from the
    /// curve into `a`'s isomorphic frame (scale `s`): 9M + 3S. How G's
    /// entries meet an accumulator that lives in P's table frame.
    fn addGeScaled(a: Jw, b: Gw, s: F) Jw {
        if (a.inf) {
            const s2 = s.sq();
            return .{ .x = b.x.mul(s2), .y = b.y.mul(s2.mul(s)), .z = F.one, .inf = false };
        }
        return addCore(a, b, a.z.mul(s)).p;
    }

    /// The mixed-addition core. `az` is `a.z` times the frame scale of `b`
    /// (1 when `b` is already in `a`'s frame). Returns the sum and `h` with
    /// `Z3 = a.z·h` — the z-ratio the table builder records. `h = 0` is the
    /// special case `ψ(b) = ±a`: double, or the identity.
    fn addCore(a: Jw, b: Gw, az: F) struct { p: Jw, h: F } {
        const z12 = az.sq();
        const u_2 = b.x.mul(z12);
        const s_2 = b.y.mul(z12).mul(az);
        const h = u_2.sub(a.x);
        const i = s_2.sub(a.y);
        if (h.isZero()) {
            return .{ .p = if (i.isZero()) a.dbl() else infinity, .h = F.zero };
        }
        const h2 = h.sq();
        const h3 = h.mul(h2);
        const t = a.x.mul(h2);
        const x3 = i.sq().sub(h3).sub(t.dbl());
        const y3 = i.mul(t.sub(x3)).sub(h3.mul(a.y));
        const z3 = a.z.mul(h);
        return .{ .p = .{ .x = x3, .y = y3, .z = z3, .inf = false }, .h = h };
    }
};

/// The odd multiples `(2i+1)·a`, `i < n`, as affine points of ONE isomorphic
/// frame, and that frame's scale `s` (entry `i` is `ψ_s((2i+1)·a)`).
/// libsecp256k1's `ecmult_odd_multiples_table` + `ge_table_set_globalz`:
///
///   1. `d = 2a`; treat `(d.x, d.y)` as affine in the frame of scale `d.z`,
///      and map `a` into that frame (`x·d.z²`, `y·d.z³`, same `Z`).
///   2. `a_i = a_{i−1} + d` by mixed addition, recording `zr_i = Z_i / Z_{i−1}`.
///   3. Walk back from the last entry, scaling entry `i` by
///      `Z_last / Z_i = zr_{i+1}·…·zr_last` (squared for x, cubed for y): all
///      entries now share `Z_last`, i.e. are affine in the frame of scale
///      `d.z·Z_last`.
///
/// `a` must not be the identity. Every addition is then generic: `a_{i−1} = ±d`
/// would mean `(2i−1)·a = ±2a`, i.e. a point of order ≤ 2i+1 < n.
fn oddMultiplesGlobalZ(comptime n: usize, a: Jw, out: *[n]Gw) F {
    const d = a.dbl();
    const d_ge = Gw{ .x = d.x, .y = d.y };
    const zd2 = d.z.sq();
    var ai = Jw{ .x = a.x.mul(zd2), .y = a.y.mul(zd2.mul(d.z)), .z = a.z, .inf = false };
    var zr: [n]F = undefined;
    out[0] = .{ .x = ai.x, .y = ai.y };
    for (1..n) |i| {
        const r = Jw.addCore(ai, d_ge, ai.z);
        if (r.h.isZero()) @panic("k256 ecmult: odd-multiple table hit a = ±2a (point of small order)");
        ai = r.p;
        zr[i] = r.h;
        out[i] = .{ .x = ai.x, .y = ai.y };
    }
    var zs = F.one;
    var i: usize = n - 1;
    while (i > 0) : (i -= 1) {
        zs = zs.mul(zr[i]);
        const zs2 = zs.sq();
        out[i - 1] = .{ .x = out[i - 1].x.mul(zs2), .y = out[i - 1].y.mul(zs2.mul(zs)) };
    }
    return ai.z.mul(d.z);
}

/// φ on a table: `φ(x, y) = (β·x, y)`. φ commutes with every frame map `ψ_s`
/// (both scale coordinates), so a table and its image share one frame.
fn phiTable(comptime n: usize, tab: *const [n]Gw) [n]Gw {
    const beta = comptime F.of(Fe.fromInt(scalarmod.beta) catch unreachable);
    var out: [n]Gw = undefined;
    for (tab, &out) |t, *o| o.* = .{ .x = t.x.mul(beta), .y = t.y };
    return out;
}

// ── GLV split + wNAF recoding (public scalars) ──────────────────────────────

/// One signed GLV half: `|r|` and its sign.
pub const GlvHalf = struct { mag: u256, negative: bool };

/// Reduce a raw 256-bit scalar mod `n` and split it into the two signed GLV
/// halves of `k ≡ r1 + r2·λ (mod n)`. Returns null when `k ≡ 0 (mod n)` (the
/// multiple is the identity). Reducing first is legal for any raw scalar
/// because the curve group has prime order `n` (`s·P = (s mod n)·P`) — the
/// portable double-and-add scans raw bits and agrees for the same reason.
///
/// Since 2026-11-13 over the integers (`splitInteger`), not through std's
/// Montgomery scalar field: the lattice gives both halves exactly, so no
/// reduction mod `n` is needed. Same halves as the `splitScalar` route
/// (`splitToSignedHalvesViaScalar`, its test oracle).
pub fn splitToSignedHalves(s_raw: u256) ?[2]GlvHalf {
    const n = scalarmod.field_order;
    // 2^256 < 2n, so a single conditional subtract fully reduces.
    const s = if (s_raw >= n) s_raw - n else s_raw;
    if (s == 0) return null;
    return splitInteger(s);
}

/// The lattice basis `{(a1, b1), (a2, b2)}` of `{(x, y) : x + y·λ ≡ 0 (mod n)}`
/// (Guide to ECC §3.5; `b1 = −glv_b1_neg`, `b2 = a1`, `a2 = a1 − b1`), and the
/// rounded multipliers `g1 = round(2^384·b2/n)`, `g2 = round(2^384·(−b1)/n)`.
const lat_a1: i320 = 64502973549206556628585045361533709077;
const lat_b1: i320 = -303414439467246543595250775667605759171;
const lat_a2: i320 = lat_a1 - lat_b1;
const lat_b2: i320 = lat_a1;

/// `k = k1 + k2·λ (mod n)` for `0 < k < n`, exactly: `c_i = round(k·g_i /
/// 2^384)`, `k2 = −c1·b1 − c2·b2`, `k1 = k − c1·a1 − c2·a2` over the integers
/// (`k1 + k2·λ = k − c1·(a1 + b1·λ) − c2·(a2 + b2·λ) ≡ k`). Products stay
/// below 2^260, so `i320` holds every intermediate.
fn splitInteger(k: u256) [2]GlvHalf {
    const t1 = math.mulWide(u256, k, scalarmod.glv_g1);
    const t2 = math.mulWide(u256, k, scalarmod.glv_g2);
    const c1: i320 = @as(u128, @truncate(t1 >> 384)) + @as(i320, @as(u1, @truncate(t1 >> 383)));
    const c2: i320 = @as(u128, @truncate(t2 >> 384)) + @as(i320, @as(u1, @truncate(t2 >> 383)));
    const k2 = -c1 * lat_b1 - c2 * lat_b2;
    const k1 = @as(i320, k) - c1 * lat_a1 - c2 * lat_a2;
    return .{ signedHalf(k1), signedHalf(k2) };
}

fn signedHalf(v: i320) GlvHalf {
    return .{ .mag = @intCast(@abs(v)), .negative = v < 0 };
}

/// The previous route (`scalarmod.splitScalar`, std's scalar field, then
/// `glvHalf`): the oracle `splitInteger` is tested against.
fn splitToSignedHalvesViaScalar(s_raw: u256) ?[2]GlvHalf {
    const n = scalarmod.field_order;
    const s = if (s_raw >= n) s_raw - n else s_raw;
    if (s == 0) return null;
    var sb: [32]u8 = undefined;
    std.mem.writeInt(u256, &sb, s, .little);
    // s < n is canonical and every intermediate of the split is in range.
    const split = scalarmod.splitScalar(sb, .little) catch unreachable;
    return .{ glvHalf(split.r1), glvHalf(split.r2) };
}

/// Resolve one split residue to a signed magnitude. A residue with any high
/// bit set represents the negative `−(n − r)` (the balanced split guarantees
/// |r| ≈ √n, so the two cases are cleanly separated by bit 128). Either
/// interpretation is ≡ r (mod n), so correctness never depends on the
/// threshold — only the ~128-bit magnitude (and hence the halved doubling
/// count) does.
fn glvHalf(r_le: [32]u8) GlvHalf {
    const v = std.mem.readInt(u256, &r_le, .little);
    if ((v >> 128) != 0) return .{ .mag = scalarmod.field_order - v, .negative = true };
    return .{ .mag = v, .negative = false };
}

/// wNAF digit-string length: a 256-bit magnitude yields at most 257 digits.
pub const wnaf_len = 257;

/// Width-`w` wNAF digit string: nonzero digits are odd, in
/// `[−(2^(w−1)−1), 2^(w−1)−1]`, at least `w−1` zeros apart. The half's sign is
/// folded into the digits.
pub fn wnafDigits(comptime w: u5, h: GlvHalf) [wnaf_len]i16 {
    comptime std.debug.assert(w >= 2 and w <= 15);
    const full: u32 = 1 << w;
    const half: i32 = 1 << (w - 1);
    var e = @as([wnaf_len]i16, @splat(0));
    var v = h.mag;
    var i: usize = 0;
    while (v != 0) : (i += 1) {
        // Skip the run of zero bits in one step (2026-11-13; it was one
        // 256-bit shift per bit): same digits, ~w× fewer wide shifts.
        const z: u8 = @intCast(@ctz(v));
        v >>= z;
        i += z;
        const r: i32 = @intCast(@as(u32, @truncate(v)) & (full - 1));
        const d: i32 = if (r >= half) r - @as(i32, @intCast(full)) else r;
        if (d >= 0) {
            v -= @as(u256, @intCast(d));
        } else {
            v += @as(u256, @intCast(-d));
        }
        e[i] = @intCast(if (h.negative) -d else d);
        v >>= 1;
    }
    return e;
}

/// Number of digit positions up to the highest nonzero digit of any string.
fn topDigit(strings: []const [wnaf_len]i16) usize {
    var top: usize = 0;
    for (strings) |e| {
        var i: usize = wnaf_len;
        while (i > top) {
            i -= 1;
            if (e[i] != 0) {
                top = i + 1;
                break;
            }
        }
    }
    return top;
}

/// `±tab[(|d|−1)/2]` for an odd nonzero digit `d`.
inline fn tableEntry(tab: []const Gw, d: i16) Gw {
    if (d > 0) return tab[@intCast(@divExact(d - 1, 2))];
    return tab[@intCast(@divExact(-d - 1, 2))].neg();
}

/// `tableEntry` over G's canonical comptime table.
inline fn gTableEntry(tab: []const Ge, d: i16) Gw {
    if (d > 0) return Gw.of(tab[@intCast(@divExact(d - 1, 2))]);
    return Gw.of(tab[@intCast(@divExact(-d - 1, 2))]).neg();
}

// ── the tables and the multiply ─────────────────────────────────────────────

/// wNAF width for P's halves: 8 odd multiples per table, built per call.
const p_window = 5;
const p_tab_len = 1 << (p_window - 2);

/// wNAF width for G's halves: the table is a comptime constant, so it can be
/// wide (fewer additions per verify) at the price of `.rodata`:
/// 2 tables × 2^(w−2) entries × 64 B.
pub const g_window = 10;
const g_tab_len = 1 << (g_window - 2);

/// `[0]`: `(2i+1)·G`, `[1]`: `φ` of the same, both truly affine.
pub const GTables = [2][g_tab_len]Ge;

/// Build G's tables at comptime: the odd-multiple builder above (portable
/// field path inside the comptime interpreter), then one inversion of the
/// frame scale maps the entries back onto the curve itself.
fn buildGTables() GTables {
    @setEvalBranchQuota(200_000_000);
    const g = Jw{
        .x = F.of(Fe.fromInt(55066263022277343669578718895168534326250603453777594175500187360389116729240) catch unreachable),
        .y = F.of(Fe.fromInt(32670510020758816978083085130507043184471273380659243275938904335757337482424) catch unreachable),
        .z = F.one,
        .inf = false,
    };
    var framed: [g_tab_len]Gw = undefined;
    const s = oddMultiplesGlobalZ(g_tab_len, g, &framed);
    const sinv = F.of(s.fe().invert());
    const sinv2 = sinv.sq();
    const sinv3 = sinv2.mul(sinv);
    var tw: [g_tab_len]Gw = undefined;
    for (framed, &tw) |f, *t| t.* = .{ .x = f.x.mul(sinv2), .y = f.y.mul(sinv3) };
    const phi = phiTable(g_tab_len, &tw);
    var tabs: GTables = undefined;
    for (tw, phi, &tabs[0], &tabs[1]) |a, b, *ta, *tb| {
        ta.* = .{ .x = a.x.fe(), .y = a.y.fe() };
        tb.* = .{ .x = b.x.fe(), .y = b.y.fe() };
    }
    return tabs;
}

/// G's affine odd-multiple tables (public constant; see `buildGTables`).
pub const g_tables: GTables = buildGTables();

/// `g_scalar·G + p_scalar·p` for PUBLIC raw 256-bit scalars and a public,
/// non-identity Jacobian `p`. Null when the result is the identity. Variable
/// time in everything.
pub fn mulDoubleBaseG(g_scalar: u256, p: Gej, p_scalar: u256) ?Gej {
    return mulDoubleBaseGWithTables(&g_tables, g_scalar, p, p_scalar);
}

/// `mulDoubleBaseG` parameterised on G's tables, so a test can pass a
/// corrupted table and prove the differential notices.
pub fn mulDoubleBaseGWithTables(gt: *const GTables, g_scalar: u256, p: Gej, p_scalar: u256) ?Gej {
    return strauss(1, gt, g_scalar, &.{p}, &.{p_scalar});
}

/// Most points one `mulMultiG` call takes: their tables and digit strings live
/// on the stack (~2 KiB per point). Callers with more points split the sum.
pub const multi_max_points = 16;

/// `g_scalar·G + Σ scalars[j]·points[j]` for PUBLIC raw scalars and public,
/// non-identity Jacobian points (1 ≤ `points.len` ≤ `multi_max_points`,
/// `scalars.len == points.len`). Null when the result is the identity.
/// Variable time in everything — the batch verifier's one big multiply.
pub fn mulMultiG(g_scalar: u256, points: []const Gej, scalars: []const u256) ?Gej {
    return strauss(multi_max_points, &g_tables, g_scalar, points, scalars);
}

/// Interleaved (Straus) GLV+wNAF multiply over G's comptime tables and up
/// to `max` per-call point tables, sharing ONE doubling chain.
///
/// One frame for every point: `oddMultiplesGlobalZ` leaves table `j` affine
/// in the frame of scale `s_j`. The common frame is `S = Π s_j`; table `j`
/// reaches it through `t_j = S / s_j = Π_{i≠j} s_i` (x·t², y·t³), and the
/// `t_j` come from prefix and suffix products — no inversion. G's entries
/// enter that frame through `S` (`addGeScaled`), and `S` is multiplied back
/// into the result's `Z` at the end.
fn strauss(comptime max: usize, gt: *const GTables, g_scalar: u256, points: []const Gej, scalars: []const u256) ?Gej {
    const k = points.len;
    std.debug.assert(k >= 1 and k <= max and scalars.len == k);
    const zero = [2]GlvHalf{ .{ .mag = 0, .negative = false }, .{ .mag = 0, .negative = false } };

    // Strings 0, 1: G and φ(G); then 2 + 2j, 3 + 2j: point j and φ(point j).
    var es: [2 + 2 * max][wnaf_len]i16 = undefined;
    const hg = splitToSignedHalves(g_scalar) orelse zero;
    es[0] = wnafDigits(g_window, hg[0]);
    es[1] = wnafDigits(g_window, hg[1]);
    var tabs: [max][2][p_tab_len]Gw = undefined;
    var scales: [max]F = undefined;
    for (points, scalars, 0..) |p, sc, j| {
        std.debug.assert(!p.inf);
        const h = splitToSignedHalves(sc) orelse zero;
        es[2 + 2 * j] = wnafDigits(p_window, h[0]);
        es[3 + 2 * j] = wnafDigits(p_window, h[1]);
        scales[j] = oddMultiplesGlobalZ(p_tab_len, Jw.of(p), &tabs[j][0]);
    }
    var scale = scales[0];
    if (k > 1) {
        var prefix: [max]F = undefined;
        var acc = F.one;
        for (0..k) |j| {
            prefix[j] = acc;
            acc = acc.mul(scales[j]);
        }
        scale = acc;
        var suffix = F.one;
        var j = k;
        while (j > 0) {
            j -= 1;
            const t = prefix[j].mul(suffix);
            suffix = suffix.mul(scales[j]);
            const t2 = t.sq();
            const t3 = t2.mul(t);
            for (&tabs[j][0]) |*e| e.* = .{ .x = e.x.mul(t2), .y = e.y.mul(t3) };
        }
    }
    for (tabs[0..k]) |*t| t[1] = phiTable(p_tab_len, &t[0]);

    const strings = es[0 .. 2 + 2 * k];
    var r = Jw.infinity;
    var i = topDigit(strings);
    while (i > 0) {
        i -= 1;
        r = r.dbl();
        if (strings[0][i] != 0) r = r.addGeScaled(gTableEntry(&gt[0], strings[0][i]), scale);
        if (strings[1][i] != 0) r = r.addGeScaled(gTableEntry(&gt[1], strings[1][i]), scale);
        for (tabs[0..k], 0..) |*t, j| {
            const d0 = strings[2 + 2 * j][i];
            const d1 = strings[3 + 2 * j][i];
            if (d0 != 0) r = r.addGe(tableEntry(&t[0], d0));
            if (d1 != 0) r = r.addGe(tableEntry(&t[1], d1));
        }
    }
    if (r.inf) return null;
    r.z = r.z.mul(scale);
    return r.gej();
}

test "splitInteger == the splitScalar route on edges and random scalars, and reconstructs k" {
    const n = scalarmod.field_order;
    const lam = scalarmod.Scalar.fromBytes(leInt(scalarmod.lambda), .little) catch unreachable;
    var prng = std.Random.DefaultPrng.init(0x5B117_1A3B);
    const rand = prng.random();
    const edges = [_]u256{ 1, 2, n - 1, n - 2, n >> 1, (n >> 1) + 1, scalarmod.lambda, n - scalarmod.lambda, 1 << 128, (1 << 128) - 1, 1 << 255 };
    for (0..4000 + edges.len) |i| {
        var k: u256 = if (i < edges.len) edges[i] else rand.int(u256);
        if (k >= n) k -= n;
        if (k == 0) continue;
        const got = splitToSignedHalves(k).?;
        const want = splitToSignedHalvesViaScalar(k).?;
        for (got, want) |g, w| {
            try std.testing.expectEqual(w.mag, g.mag);
            try std.testing.expectEqual(w.negative, g.negative);
            try std.testing.expect(g.mag < (1 << 129));
        }
        // k1 + k2·λ ≡ k (mod n), with the signs applied.
        const k1 = scalarmod.Scalar.fromBytes(leInt(got[0].mag), .little) catch unreachable;
        const k2 = scalarmod.Scalar.fromBytes(leInt(got[1].mag), .little) catch unreachable;
        const s1 = if (got[0].negative) k1.neg() else k1;
        const s2 = if (got[1].negative) k2.neg() else k2;
        const kk = scalarmod.Scalar.fromBytes(leInt(k), .little) catch unreachable;
        try std.testing.expect(s1.add(s2.mul(lam)).equivalent(kk));
    }
}

fn leInt(x: u256) [32]u8 {
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, x, .little);
    return b;
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// The differential oracle is `group.Secp256k1.mulDoubleBasePublicDoubleAdd`
// (plain interleaved double-and-add on the complete RCB law, itself pinned to
// std) and std's own `mulDoubleBasePublic`.

const builtin = @import("builtin");
const group = @import("group.zig");
const Secp256k1 = group.Secp256k1;
const Std = std.crypto.ecc.Secp256k1;

fn toJacobian(p: Secp256k1) Gej {
    const z2 = p.z.sq();
    return .{ .x = p.x.mul(p.z), .y = p.y.mul(z2), .z = p.z, .inf = false };
}

fn affineOf(r: ?Gej) ?[2]u256 {
    const j = r orelse return null;
    const zi = j.z.invert();
    const zi2 = zi.sq();
    return .{ j.x.mul(zi2).toInt(), j.y.mul(zi2.mul(zi)).toInt() };
}

fn oracle(g_scalar: u256, p: Secp256k1, p_scalar: u256) ?[2]u256 {
    var gb: [32]u8 = undefined;
    var pb: [32]u8 = undefined;
    std.mem.writeInt(u256, &gb, g_scalar, .big);
    std.mem.writeInt(u256, &pb, p_scalar, .big);
    const q = Secp256k1.mulDoubleBasePublicDoubleAdd(Secp256k1.basePoint, gb, p, pb, .big) catch return null;
    const a = q.affineCoordinates();
    return .{ a.x.toInt(), a.y.toInt() };
}

fn expectSame(g_scalar: u256, p: Secp256k1, p_scalar: u256) !void {
    const want = oracle(g_scalar, p, p_scalar);
    const got = affineOf(mulDoubleBaseG(g_scalar, toJacobian(p), p_scalar));
    if (want) |w| {
        const gv = got orelse return error.TestUnexpectedIdentity;
        try std.testing.expectEqual(w[0], gv[0]);
        try std.testing.expectEqual(w[1], gv[1]);
    } else {
        try std.testing.expect(got == null);
    }
}

/// `x mod p` for the weak-form oracle.
fn modP(x: u512) u256 {
    return @intCast(x % p_int);
}

test "ecmult: weak field ops == integer arithmetic mod p, incl. the rare second folds" {
    // Edges: both representatives of 0, values within c of 2^256 (where the
    // second fold of add/sub/mulSmall and mul's cf2 branch fire), and odd
    // values near 2^256 (half's 257th bit).
    const top = ~@as(u256, 0);
    const edges = [_]u256{
        0,              1,         2,         c_fold - 1,      c_fold,       c_fold + 1, p_int - 1,      p_int,
        p_int + 1,      p_int + 2, top - 1,   top,             top - c_fold, 1 << 255,   (1 << 255) - 1, 1 << 128,
        (1 << 192) + 7, top >> 1,  top - 977, top - (1 << 32),
    };
    var prng = std.Random.DefaultPrng.init(0xEC_3017_F00D);
    const rand = prng.random();
    var hits: [4]usize = @splat(0); // second fold of add, sub; mul result ≥ p; half carry
    for (0..edges.len * edges.len + 3000) |i| {
        const a: u256 = if (i < edges.len * edges.len) edges[i / edges.len] else rand.int(u256);
        const b: u256 = if (i < edges.len * edges.len) edges[i % edges.len] else rand.int(u256);
        const fa = F{ .v = a };
        const fb = F{ .v = b };
        const s = fa.add(fb);
        try std.testing.expectEqual(modP(@as(u512, a) + b), modP(s.v));
        if (@addWithOverflow(@addWithOverflow(a, b)[0], c_fold)[1] == 1 and @addWithOverflow(a, b)[1] == 1) hits[0] += 1;
        const d = fa.sub(fb);
        try std.testing.expectEqual(modP(@as(u512, a) + 2 * @as(u512, p_int) - b), modP(d.v));
        if (a < b and @subWithOverflow(a, b)[0] < c_fold) hits[1] += 1;
        const m = fa.mul(fb);
        try std.testing.expectEqual(modP(@as(u512, a) * b), modP(m.v));
        if (m.v >= p_int) hits[2] += 1;
        try std.testing.expectEqual(modP(@as(u512, a) * a), modP(fa.sq().v));
        try std.testing.expectEqual(modP(@as(u512, a) * 3), modP(fa.mulSmall(3).v));
        try std.testing.expectEqual(modP(@as(u512, a) * 8), modP(fa.mulSmall(8).v));
        const h = fa.half();
        try std.testing.expectEqual(modP(@as(u512, a)), modP(@as(u512, h.v) * 2));
        if (a & 1 == 1 and @addWithOverflow(a, p_int)[1] == 1) hits[3] += 1;
        try std.testing.expectEqual(modP(a) == 0, modP(fa.neg().v) == 0);
        try std.testing.expectEqual(modP(@as(u512, a) + modP(fa.neg().v)), 0);
        try std.testing.expectEqual(modP(a) == 0, fa.isZero());
        try std.testing.expectEqual(modP(a), fa.fe().toInt());
    }
    // The edge set reaches every rare branch.
    for (hits) |n| try std.testing.expect(n > 0);
}

test "ecmult: G tables are the affine odd multiples of G and φ(G)" {
    var acc = Secp256k1.basePoint;
    const two_g = acc.dbl();
    const beta = Fe.fromInt(scalarmod.beta) catch unreachable;
    for (0..g_tab_len) |i| {
        const a = acc.affineCoordinates();
        try std.testing.expectEqual(a.x.toInt(), g_tables[0][i].x.toInt());
        try std.testing.expectEqual(a.y.toInt(), g_tables[0][i].y.toInt());
        try std.testing.expectEqual(a.x.mul(beta).toInt(), g_tables[1][i].x.toInt());
        try std.testing.expectEqual(a.y.toInt(), g_tables[1][i].y.toInt());
        acc = acc.add(two_g);
    }
}

const ecmult_random_iters: usize = if (builtin.mode == .debug) 60 else 600;

test "ecmult: s1·G + s2·P == double-and-add oracle, random scalars and points" {
    var prng = std.Random.DefaultPrng.init(0xEC_3017_0001);
    const rand = prng.random();
    for (0..ecmult_random_iters) |_| {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        const p = Secp256k1.basePoint.mulPublic(kb, .big) catch continue;
        const s1 = rand.int(u256);
        const s2 = rand.int(u256);
        try expectSame(s1, p, s2);
        // A projective representative with z ≠ 1 must give the same point.
        try expectSame(s1, p.add(Secp256k1.identityElement), s2);
        // And against std directly.
        var b1: [32]u8 = undefined;
        var b2: [32]u8 = undefined;
        std.mem.writeInt(u256, &b1, s1, .big);
        std.mem.writeInt(u256, &b2, s2, .big);
        const sp = Std.basePoint.mulPublic(kb, .big) catch continue;
        const want = (Std.mulDoubleBasePublic(Std.basePoint, b1, sp, b2, .big) catch continue).affineCoordinates();
        const got = affineOf(mulDoubleBaseG(s1, toJacobian(p), s2)).?;
        try std.testing.expectEqual(want.x.toInt(), got[0]);
        try std.testing.expectEqual(want.y.toInt(), got[1]);
    }
}

test "ecmult: edge scalars × special points (G, −G, 2G, φ(G), random), identity results" {
    const n = scalarmod.field_order;
    const lambda = scalarmod.lambda;
    const scalars = [_]u256{
        0,             1,                 2,      3,          15,       16,             17,
        255,           256,               n - 1,  n - 2,      n - 15,   n,              n + 1,
        (n - 1) / 2,   (n + 1) / 2,       lambda, n - lambda, 1 << 128, (1 << 128) - 1, (1 << 255),
        ~@as(u256, 0), ~@as(u256, 0) - 1,
    };
    const g = Secp256k1.basePoint;
    const beta = Fe.fromInt(scalarmod.beta) catch unreachable;
    var rb: [32]u8 = undefined;
    std.mem.writeInt(u256, &rb, 0x1234_5678_9ABC_DEF0_1122_3344_5566_7788, .big);
    const pts = [_]Secp256k1{
        g,
        g.neg(),
        g.dbl(),
        .{ .x = g.x.mul(beta), .y = g.y, .z = g.z }, // φ(G) = λ·G
        (try g.mulPublic(rb, .big)).dbl(), // a projective z ≠ 1
    };
    for (pts) |p| {
        for (scalars) |s1| {
            for (scalars) |s2| try expectSame(s1, p, s2);
        }
    }
    // Cancellations: s1·G + s2·(kG) = O exactly when s1 + s2·k ≡ 0.
    const ks = [_]u256{ 1, 2, 7, lambda, n - 1 };
    for (ks) |k| {
        var kb: [32]u8 = undefined;
        std.mem.writeInt(u256, &kb, k, .big);
        const p = try g.mulPublic(kb, .big);
        for ([_]u256{ 1, 3, 1 << 200, n - 5 }) |s2| {
            const prod = @as(u512, s2) * k % n;
            const s1: u256 = @intCast((n - prod) % n);
            try std.testing.expect(mulDoubleBaseG(s1, toJacobian(p), s2) == null);
            try expectSame(s1, p, s2);
            try expectSame(s1 +% 1, p, s2); // one step off: G itself
        }
    }
}

test "ecmult: a corrupted G table is caught (the differential has teeth)" {
    var bad = g_tables;
    bad[0][3].y = bad[0][3].y.neg(); // 7G → −7G
    const s1: u256 = 7; // wNAF(7) = single digit 7 → hits entry 3
    const p = Secp256k1.basePoint.dbl();
    const got = affineOf(mulDoubleBaseGWithTables(&bad, s1, toJacobian(p), 0)).?;
    const want = oracle(s1, p, 0).?;
    try std.testing.expect(got[1] != want[1]);
}

test "ecmult: wnafDigits reconstructs the magnitude for every window" {
    var prng = std.Random.DefaultPrng.init(0x3A_F5);
    const rand = prng.random();
    inline for (.{ 2, 4, 5, 8, 12 }) |w| {
        for (0..200) |_| {
            const h = GlvHalf{ .mag = rand.int(u130), .negative = rand.boolean() };
            const e = wnafDigits(w, h);
            var acc: i512 = 0;
            var i: usize = wnaf_len;
            var last_nz: ?usize = null;
            while (i > 0) {
                i -= 1;
                acc = acc * 2 + e[i];
                if (e[i] != 0) {
                    try std.testing.expect(@mod(e[i], 2) != 0);
                    try std.testing.expect(@abs(e[i]) < (1 << (w - 1)));
                    if (last_nz) |l| try std.testing.expect(l - i >= w);
                    last_nz = i;
                }
            }
            const want: i512 = if (h.negative) -@as(i512, h.mag) else h.mag;
            try std.testing.expectEqual(want, acc);
        }
    }
}

/// `g·G + Σ s_j·P_j` the slow way: one double-and-add per term, summed with
/// the complete RCB law. Null for the identity.
fn multiOracle(g: u256, pts: []const Secp256k1, ss: []const u256) ?[2]u256 {
    var acc = Secp256k1.identityElement;
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, g, .big);
    if (Secp256k1.basePoint.mulPublicDoubleAdd(b, .big)) |t| acc = acc.add(t) else |_| {}
    for (pts, ss) |p, sc| {
        std.mem.writeInt(u256, &b, sc, .big);
        if (p.mulPublicDoubleAdd(b, .big)) |t| acc = acc.add(t) else |_| {}
    }
    acc.rejectIdentity() catch return null;
    const a = acc.affineCoordinates();
    return .{ a.x.toInt(), a.y.toInt() };
}

fn expectMultiSame(g: u256, pts: []const Secp256k1, ss: []const u256) !void {
    var js: [multi_max_points]Gej = undefined;
    for (pts, 0..) |p, j| js[j] = toJacobian(p);
    const want = multiOracle(g, pts, ss);
    const got = affineOf(mulMultiG(g, js[0..pts.len], ss));
    if (want) |w| {
        const gv = got orelse return error.TestUnexpectedIdentity;
        try std.testing.expectEqual(w[0], gv[0]);
        try std.testing.expectEqual(w[1], gv[1]);
    } else {
        try std.testing.expect(got == null);
    }
}

const multi_random_iters: usize = if (builtin.mode == .debug) 12 else 120;

test "ecmult: mulMultiG == Σ double-and-add, 1..16 random points, z ≠ 1 and duplicates" {
    var prng = std.Random.DefaultPrng.init(0xEC_3017_0002);
    const rand = prng.random();
    var pts: [multi_max_points]Secp256k1 = undefined;
    var ss: [multi_max_points]u256 = undefined;
    for (0..multi_random_iters) |it| {
        const k = 1 + it % multi_max_points;
        for (0..k) |j| {
            var kb: [32]u8 = undefined;
            rand.bytes(&kb);
            pts[j] = Secp256k1.basePoint.mulPublic(kb, .big) catch Secp256k1.basePoint;
            if (rand.boolean()) pts[j] = pts[j].add(Secp256k1.identityElement); // z ≠ 1
            ss[j] = rand.int(u256);
        }
        if (k > 2) pts[1] = pts[0]; // a duplicated base
        try expectMultiSame(rand.int(u256), pts[0..k], ss[0..k]);
        try expectMultiSame(0, pts[0..k], ss[0..k]);
    }
}

test "ecmult: mulMultiG cancellations — P and −P, and the batch-verify identity" {
    const n = scalarmod.field_order;
    const g = Secp256k1.basePoint;
    var kb: [32]u8 = undefined;
    std.mem.writeInt(u256, &kb, 0xDEAD_BEEF_0123_4567, .big);
    const p = try g.mulPublic(kb, .big);
    // s·P + s·(−P) + 0·G = O.
    try std.testing.expect(mulMultiG(0, &.{ toJacobian(p), toJacobian(p.neg()) }, &.{ 12345, 12345 }) == null);
    try expectMultiSame(0, &.{ p, p.neg() }, &.{ 12345, 12345 });
    // One step off is P.
    try expectMultiSame(0, &.{ p, p.neg() }, &.{ 12346, 12345 });
    // s·G − R − e·P = O for a real BIP340-shaped relation: R = kG, s = k + e·d.
    const d: u256 = 0x1111_2222_3333_4444_5555;
    const kk: u256 = 0x9999_8888_7777;
    const e: u256 = 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F;
    std.mem.writeInt(u256, &kb, d, .big);
    const pk = try g.mulPublic(kb, .big);
    std.mem.writeInt(u256, &kb, kk, .big);
    const r = try g.mulPublic(kb, .big);
    const s_sig: u256 = @intCast((@as(u512, kk) + @as(u512, e) * d) % n);
    const pts = [_]Secp256k1{ r, pk };
    const ss = [_]u256{ n - 1, n - e };
    try expectMultiSame(s_sig, &pts, &ss);
    try std.testing.expect(mulMultiG(s_sig, &.{ toJacobian(r), toJacobian(pk) }, &ss) == null);
    try std.testing.expect(mulMultiG(s_sig + 1, &.{ toJacobian(r), toJacobian(pk) }, &ss) != null);
}

test "ecmult: Secp256k1.mulMultiBasePublic chunks past multi_max_points; empty and identity inputs" {
    var prng = std.Random.DefaultPrng.init(0xEC_3017_0003);
    const rand = prng.random();
    const count = 2 * multi_max_points + 5; // three chunks, the last one short
    var pts: [count]Secp256k1 = undefined;
    var ss: [count]u256 = undefined;
    var sb: [count][32]u8 = undefined;
    for (0..count) |j| {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        pts[j] = try Secp256k1.basePoint.mulPublic(kb, .big);
        ss[j] = rand.int(u256);
        std.mem.writeInt(u256, &sb[j], ss[j], .big);
    }
    const g = rand.int(u256);
    var gb: [32]u8 = undefined;
    std.mem.writeInt(u256, &gb, g, .big);
    const got = (try Secp256k1.mulMultiBasePublic(gb, &pts, &sb, .big)).affineCoordinates();
    const want = multiOracle(g, &pts, &ss).?;
    try std.testing.expectEqual(want[0], got.x.toInt());
    try std.testing.expectEqual(want[1], got.y.toInt());

    // No points: g·G alone.
    const g_only = (try Secp256k1.mulMultiBasePublic(gb, &.{}, &.{}, .big)).affineCoordinates();
    const g_want = (try Secp256k1.basePoint.mulPublic(gb, .big)).affineCoordinates();
    try std.testing.expectEqual(g_want.x.toInt(), g_only.x.toInt());
    // An identity base, and an identity sum, are both `error.IdentityElement`.
    try std.testing.expectError(error.IdentityElement, Secp256k1.mulMultiBasePublic(gb, &.{ pts[0], Secp256k1.identityElement }, sb[0..2], .big));
    const zero = @as([32]u8, @splat(0));
    try std.testing.expectError(error.IdentityElement, Secp256k1.mulMultiBasePublic(zero, &.{ pts[0], pts[0].neg() }, &.{ sb[0], sb[0] }, .big));
}

test "affineCoordinatesPublic == affineCoordinates (random projective points, identity)" {
    var prng = std.Random.DefaultPrng.init(0xAFF1_E0B5);
    const rand = prng.random();
    for (0..200) |_| {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        var p = Secp256k1.basePoint.mulPublic(kb, .big) catch continue;
        p = p.add(Secp256k1.basePoint.dbl()); // a z far from 1
        const want = p.affineCoordinates();
        const got = p.affineCoordinatesPublic();
        try std.testing.expectEqual(want.x.toInt(), got.x.toInt());
        try std.testing.expectEqual(want.y.toInt(), got.y.toInt());
    }
    const o = Secp256k1.identityElement;
    try std.testing.expectEqual(o.affineCoordinates().x.toInt(), o.affineCoordinatesPublic().x.toInt());
    try std.testing.expectEqual(o.affineCoordinates().y.toInt(), o.affineCoordinatesPublic().y.toInt());
}

// Mutation run 2026-10-08: with G as the SECOND base the dispatch could pass
// the two scalars swapped and the suite stayed green — every caller puts G
// first. Distinct scalars, G in either position, against the double-add oracle.
test "mulDoubleBasePublic: G as the second base takes its own scalar" {
    var kb: [32]u8 = undefined;
    std.mem.writeInt(u256, &kb, 0xC0DE_F00D_1234, .big);
    const p = try Secp256k1.basePoint.mulPublic(kb, .big);
    const g = Secp256k1.basePoint;
    var s1: [32]u8 = undefined;
    var s2: [32]u8 = undefined;
    std.mem.writeInt(u256, &s1, 0x1111_2222_3333, .big);
    std.mem.writeInt(u256, &s2, 0x9999_8888_7777_6666, .big);
    const want = (try Secp256k1.mulDoubleBasePublicDoubleAdd(p, s1, g, s2, .big)).affineCoordinates();
    const got = (try Secp256k1.mulDoubleBasePublic(p, s1, g, s2, .big)).affineCoordinates();
    try std.testing.expectEqual(want.x.toInt(), got.x.toInt());
    try std.testing.expectEqual(want.y.toInt(), got.y.toInt());
    const got_g_first = (try Secp256k1.mulDoubleBasePublic(g, s2, p, s1, .big)).affineCoordinates();
    try std.testing.expectEqual(want.x.toInt(), got_g_first.x.toInt());
}

// Mutation run 2026-10-08: the `z = 0` test in `affineCoordinatesPublic` could
// go and the suite stayed green, because the only identity it saw was the
// constant `(0 : 1 : 0)`, which the affine-(0, 1) test also catches. The
// complete law's `P + (−P)` is `(0 : Y : 0)` with any `Y`.
test "affineCoordinatesPublic: an identity with z = 0 and y ∉ {0, 1}" {
    var kb: [32]u8 = undefined;
    std.mem.writeInt(u256, &kb, 0xABCDEF, .big);
    const p = try Secp256k1.basePoint.mulPublic(kb, .big);
    const o = p.add(p.neg());
    try std.testing.expect(o.z.isZero());
    try std.testing.expect(!o.y.isZero() and !o.y.equivalent(Fe.one));
    const want = o.affineCoordinates();
    const got = o.affineCoordinatesPublic();
    try std.testing.expectEqual(want.x.toInt(), got.x.toInt());
    try std.testing.expectEqual(want.y.toInt(), got.y.toInt());
}
