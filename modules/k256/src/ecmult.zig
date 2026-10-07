// SPDX-License-Identifier: MIT

//! ecmult — VARIABLE-TIME `s1·G + s2·P` for PUBLIC scalars: the verifier's
//! `s·G − e·P` when one base is the generator (BIP340, ECDSA, adaptor).
//! libsecp256k1's `ecmult` design, re-derived on k256's `Fe`:
//!
//!   * **Jacobian coordinates** `(X, Y, Z)` ↦ `(X/Z², Y/Z³)` with the
//!     incomplete `a = 0` formulas — doubling 2M + 5S (dbl-2009-l), mixed
//!     addition 8M + 3S — where `group.zig`'s complete RCB law pays 6M + 2S
//!     and 12M. Incomplete means the special cases (identity, `a = ±b`) are
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
//!   * **G's table precomputed affine** at comptime with a wider window
//!     (`g_window`), together with `φ(G)`'s (`(β·x, y)`); its entries enter the
//!     isomorphic frame through the same common `Z` (`addGeScaled`).
//!
//! `group.Secp256k1.mulDoubleBasePublic` dispatches here when one base is
//! `basePoint` exactly, so every consumer gets it without an API change. The
//! RCB GLV path (`glvCombine`) and the plain double-and-add stay the oracles.

const std = @import("std");
const field = @import("field.zig");
const scalarmod = @import("scalar.zig");

const Fe = field.Fe;

/// An affine point. Never the identity: tables hold odd multiples of a point
/// of prime order.
pub const Ge = struct {
    x: Fe,
    y: Fe,

    fn neg(a: Ge) Ge {
        return .{ .x = a.x, .y = a.y.neg() };
    }
};

/// A Jacobian point; `inf` marks the identity (its coordinates are then
/// meaningless).
pub const Gej = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    inf: bool,

    pub const infinity = Gej{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero, .inf = true };

    fn fromGe(a: Ge) Gej {
        return .{ .x = a.x, .y = a.y, .z = Fe.one, .inf = false };
    }

    /// `2a`, dbl-2009-l for `a = 0`: 2M + 5S. secp256k1 has no point of order
    /// two (its order is an odd prime), so `Y = 0` never occurs.
    fn dbl(a: Gej) Gej {
        if (a.inf) return a;
        const xx = a.x.sq();
        const yy = a.y.sq();
        const yyyy = yy.sq();
        const d = a.x.add(yy).sq().sub(xx).sub(yyyy).dbl();
        const e = xx.mulSmall(3);
        const x3 = e.sq().sub(d.dbl());
        const y3 = e.mul(d.sub(x3)).sub(yyyy.mulSmall(8));
        const z3 = a.y.mul(a.z).dbl();
        return .{ .x = x3, .y = y3, .z = z3, .inf = false };
    }

    /// `a + b` for `b` affine in `a`'s frame (mixed addition, 8M + 3S).
    fn addGe(a: Gej, b: Ge) Gej {
        if (a.inf) return fromGe(b);
        return addCore(a, b, a.z).p;
    }

    /// `a + ψ(b)` where `ψ(x, y) = (s²·x, s³·y)` maps the affine `b` from the
    /// curve into `a`'s isomorphic frame (scale `s`): 9M + 3S. How G's
    /// entries meet an accumulator that lives in P's table frame.
    fn addGeScaled(a: Gej, b: Ge, s: Fe) Gej {
        if (a.inf) {
            const s2 = s.sq();
            return .{ .x = b.x.mul(s2), .y = b.y.mul(s2.mul(s)), .z = Fe.one, .inf = false };
        }
        return addCore(a, b, a.z.mul(s)).p;
    }

    /// The mixed-addition core. `az` is `a.z` times the frame scale of `b`
    /// (1 when `b` is already in `a`'s frame). Returns the sum and `h` with
    /// `Z3 = a.z·h` — the z-ratio the table builder records. `h = 0` is the
    /// special case `ψ(b) = ±a`: double, or the identity.
    fn addCore(a: Gej, b: Ge, az: Fe) struct { p: Gej, h: Fe } {
        const z12 = az.sq();
        const u_2 = b.x.mul(z12);
        const s_2 = b.y.mul(z12).mul(az);
        const h = u_2.sub(a.x);
        const i = s_2.sub(a.y);
        if (h.isZero()) {
            return .{ .p = if (i.isZero()) a.dbl() else infinity, .h = Fe.zero };
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
fn oddMultiplesGlobalZ(comptime n: usize, a: Gej, out: *[n]Ge) Fe {
    const d = a.dbl();
    const d_ge = Ge{ .x = d.x, .y = d.y };
    const zd2 = d.z.sq();
    var ai = Gej{ .x = a.x.mul(zd2), .y = a.y.mul(zd2.mul(d.z)), .z = a.z, .inf = false };
    var zr: [n]Fe = undefined;
    out[0] = .{ .x = ai.x, .y = ai.y };
    for (1..n) |i| {
        const r = Gej.addCore(ai, d_ge, ai.z);
        if (r.h.isZero()) @panic("k256 ecmult: odd-multiple table hit a = ±2a (point of small order)");
        ai = r.p;
        zr[i] = r.h;
        out[i] = .{ .x = ai.x, .y = ai.y };
    }
    var zs = Fe.one;
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
fn phiTable(comptime n: usize, tab: *const [n]Ge) [n]Ge {
    const beta = comptime (Fe.fromInt(scalarmod.beta) catch unreachable);
    var out: [n]Ge = undefined;
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
pub fn splitToSignedHalves(s_raw: u256) ?[2]GlvHalf {
    const n = scalarmod.field_order;
    // 2^256 < 2n, so a single conditional subtract fully reduces.
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
    var e = [_]i16{0} ** wnaf_len;
    var v = h.mag;
    var i: usize = 0;
    while (v != 0) : (i += 1) {
        if (@as(u1, @truncate(v)) == 1) {
            const r: i32 = @intCast(@as(u32, @truncate(v)) & (full - 1));
            const d: i32 = if (r >= half) r - @as(i32, @intCast(full)) else r;
            if (d >= 0) {
                v -= @as(u256, @intCast(d));
            } else {
                v += @as(u256, @intCast(-d));
            }
            e[i] = @intCast(if (h.negative) -d else d);
        }
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
inline fn tableEntry(tab: []const Ge, d: i16) Ge {
    if (d > 0) return tab[@intCast(@divExact(d - 1, 2))];
    return tab[@intCast(@divExact(-d - 1, 2))].neg();
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
    const g = Gej{
        .x = Fe.fromInt(55066263022277343669578718895168534326250603453777594175500187360389116729240) catch unreachable,
        .y = Fe.fromInt(32670510020758816978083085130507043184471273380659243275938904335757337482424) catch unreachable,
        .z = Fe.one,
        .inf = false,
    };
    var framed: [g_tab_len]Ge = undefined;
    const s = oddMultiplesGlobalZ(g_tab_len, g, &framed);
    const sinv = s.invert();
    const sinv2 = sinv.sq();
    const sinv3 = sinv2.mul(sinv);
    var tabs: GTables = undefined;
    for (framed, &tabs[0]) |f, *t| t.* = .{ .x = f.x.mul(sinv2), .y = f.y.mul(sinv3) };
    tabs[1] = phiTable(g_tab_len, &tabs[0]);
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
    var tabs: [max][2][p_tab_len]Ge = undefined;
    var scales: [max]Fe = undefined;
    for (points, scalars, 0..) |p, sc, j| {
        std.debug.assert(!p.inf);
        const h = splitToSignedHalves(sc) orelse zero;
        es[2 + 2 * j] = wnafDigits(p_window, h[0]);
        es[3 + 2 * j] = wnafDigits(p_window, h[1]);
        scales[j] = oddMultiplesGlobalZ(p_tab_len, p, &tabs[j][0]);
    }
    var scale = scales[0];
    if (k > 1) {
        var prefix: [max]Fe = undefined;
        var acc = Fe.one;
        for (0..k) |j| {
            prefix[j] = acc;
            acc = acc.mul(scales[j]);
        }
        scale = acc;
        var suffix = Fe.one;
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
    var r = Gej.infinity;
    var i = topDigit(strings);
    while (i > 0) {
        i -= 1;
        r = r.dbl();
        if (strings[0][i] != 0) r = r.addGeScaled(tableEntry(&gt[0], strings[0][i]), scale);
        if (strings[1][i] != 0) r = r.addGeScaled(tableEntry(&gt[1], strings[1][i]), scale);
        for (tabs[0..k], 0..) |*t, j| {
            const d0 = strings[2 + 2 * j][i];
            const d1 = strings[3 + 2 * j][i];
            if (d0 != 0) r = r.addGe(tableEntry(&t[0], d0));
            if (d1 != 0) r = r.addGe(tableEntry(&t[1], d1));
        }
    }
    if (r.inf) return null;
    r.z = r.z.mul(scale);
    return r;
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

const ecmult_random_iters: usize = if (builtin.mode == .Debug) 60 else 600;

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

const multi_random_iters: usize = if (builtin.mode == .Debug) 12 else 120;

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
    const zero = [_]u8{0} ** 32;
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
