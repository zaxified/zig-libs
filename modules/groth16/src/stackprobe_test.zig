// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every entry point that holds a Groth16 prover
//! secret: `prover.setup` (the five toxic-waste scalars), `prover.prove` and
//! `zkprove.prove` (witness, randomizers `r`/`s`, the QAP quotient),
//! `phase2.contribute` (`x`, `s`) and `circom.parseWitness` (witness decoded
//! from a `.wtns`). Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `bls12_381`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets. For
//! `zkprove.prove` the heap the call used is scanned too (its MSM and
//! evaluation scratch is freed back to the allocator).
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in (both
//! byte orders and the in-memory Montgomery limbs): the scalars themselves,
//! and what is recomputable from them through the public API — `setup`: the
//! inverses of γ and δ, `Z(τ)`, `uᵢ(τ)`/`vᵢ(τ)`/`wᵢ(τ)`, the combined
//! `β·uᵢ+α·vᵢ+wᵢ` and its `/γ`, `/δ` forms, the `H` scalars; `prove`: `r·s`,
//! the domain evaluations of A/B/C, their interpolated coefficients, the
//! product, `A·B−C` and the quotient `H`, and the Jacobian/affine images of
//! `r·δ`, `s·δ` (G1 and G2) and `r·s·δ`. Windows with fewer than 8 distinct
//! bytes are skipped (small field elements, limb padding).
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const bn254 = @import("bn254");
const prover = @import("prover.zig");
const zkprove = @import("zkprove.zig");
const phase2 = @import("phase2.zig");
const circom = @import("circom.zig");
const zkey = @import("zkey.zig");
const r1cs = @import("r1cs.zig");
const fft = @import("fft.zig");
const poly = @import("poly.zig");
const domain = @import("domain.zig");

const Fr = bn254.Fr;
const G1 = bn254.G1;
const G2 = bn254.G2;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;

const WINDOW = 512 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 65536;

const Needles = struct {
    win: [max_windows]u128 = undefined,
    owner: [max_windows]u8 = undefined,
    len: usize = 0,
    names: [32][]const u8 = undefined,
    n_names: usize = 0,

    fn addImage(self: *Needles, name: []const u8, image: []const u8) void {
        const id: u8 = @intCast(self.lookupName(name));
        var i: usize = 0;
        while (i + W <= image.len) : (i += 1) {
            if (distinct(image[i..][0..W]) < 8) continue;
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    /// `image` big-endian and byte-reversed.
    fn addBoth(self: *Needles, name: []const u8, image: []const u8) void {
        self.addImage(name, image);
        var r: [16384]u8 = undefined;
        @memcpy(r[0..image.len], image);
        std.mem.reverse(u8, r[0..image.len]);
        self.addImage(name, r[0..image.len]);
    }

    fn distinct(w: *const [W]u8) usize {
        var seen: [256]bool = @splat(false);
        var c: usize = 0;
        for (w) |b| {
            if (!seen[b]) c += 1;
            seen[b] = true;
        }
        return c;
    }

    fn lookupName(self: *Needles, name: []const u8) usize {
        for (self.names[0..self.n_names], 0..) |n, i| if (std.mem.eql(u8, n, name)) return i;
        self.names[self.n_names] = name;
        self.n_names += 1;
        return self.n_names - 1;
    }

    /// An `Fr`: its big-endian encoding (both byte orders) and its in-memory
    /// (Montgomery limb) image.
    fn addFr(self: *Needles, name: []const u8, s: Fr) void {
        self.addBoth(name, &s.toBytes());
        self.addImage(name, std.mem.asBytes(&s));
    }

    /// The in-memory image of `*p` (any plain value).
    fn addValue(self: *Needles, name: []const u8, p: anytype) void {
        self.addImage(name, std.mem.asBytes(p));
    }

    fn reset(self: *Needles) void {
        self.len = 0;
        self.n_names = 0;
    }

    fn sort(self: *Needles) void {
        const Ctx = struct {
            n: *Needles,
            pub fn lessThan(c: @This(), a: usize, b: usize) bool {
                return c.n.win[a] < c.n.win[b];
            }
            pub fn swap(c: @This(), a: usize, b: usize) void {
                std.mem.swap(u128, &c.n.win[a], &c.n.win[b]);
                std.mem.swap(u8, &c.n.owner[a], &c.n.owner[b]);
            }
        };
        std.sort.pdqContext(0, self.len, Ctx{ .n = self });
    }

    fn find(self: *const Needles, v: u128) ?u8 {
        var lo: usize = 0;
        var hi: usize = self.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (self.win[mid] < v) lo = mid + 1 else hi = mid;
        }
        return if (lo < self.len and self.win[lo] == v) self.owner[lo] else null;
    }
};

const Hits = [32]usize;

// ── the measured region ─────────────────────────────────────────────────────
//
// The region is addressed directly, below a fixed distance (`PAD`) under the
// probe's own stack position, and the measured call runs under a `PAD`-deep
// frame (`shim`), so its frames start inside the region. `paint` and
// `snapshot` run at the probe's own depth with frames far smaller than `PAD`:
// no instrument frame overlaps the region, so even the call's shallowest
// frames (a wrapper's by-value copies) are seen.
const PAD = 2048;

var region_lo: usize = 0;
var region_hi: usize = 0;
var snap: [WINDOW]u8 = undefined;

noinline fn stackHere() usize {
    var x: u8 = 0;
    std.mem.doNotOptimizeAway(&x);
    return @intFromPtr(&x);
}

noinline fn paint() void {
    const p: [*]volatile u8 = @ptrFromInt(region_lo);
    for (0..WINDOW) |i| p[i] = 0xC7;
}

/// Run `call` `PAD` bytes deeper than the probe, so its frames lie inside the
/// region. `pad` is touched after the call too, so it cannot be a tail call.
noinline fn shim(call: *const fn () void) void {
    var pad: [PAD]u8 = undefined;
    std.mem.doNotOptimizeAway(&pad);
    call();
    std.mem.doNotOptimizeAway(&pad);
}

noinline fn snapshot() void {
    const p: [*]const volatile u8 = @ptrFromInt(region_lo);
    for (&snap, 0..) |*d, i| d.* = p[i];
}

var hit_min_depth: usize = 0;
var hit_max_depth: usize = 0;

fn scan(needles: *const Needles) Hits {
    var hits: Hits = @splat(0);
    hit_min_depth = 0;
    hit_max_depth = 0;
    var skip_until: usize = 0;
    var i: usize = 0;
    while (i + W <= WINDOW) : (i += 1) {
        if (i < skip_until) continue;
        if (needles.find(std.mem.readInt(u128, snap[i..][0..W], .little))) |id| {
            hits[id] += 1;
            const d = WINDOW - i;
            if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
            if (d > hit_max_depth) hit_max_depth = d;
            skip_until = i + W;
        }
    }
    return hits;
}

/// Residue in heap memory a call freed (or never wiped): windows of `bytes`.
fn scanHeap(needles: *const Needles, bytes: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + W <= bytes.len) : (i += 1) {
        if (needles.find(std.mem.readInt(u128, bytes[i..][0..W], .little)) != null) {
            n += 1;
            i += W - 1;
        }
    }
    return n;
}

/// When set, the heap the measured call used: scanned after every call.
var heap_view: ?[]const u8 = null;

fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    Sha256.hash("public", &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

/// Positive control: parks a secret in a stack local and returns.
var leak_src: [LEAK]u8 = undefined;
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..][0..LEAK].* = leak_src;
    std.mem.doNotOptimizeAway(&local);
}

/// Zero the callee-saved registers before a measured call: they still hold
/// the TEST's values — needles it just computed — and the call's prologue
/// spills them into its frame, where the scan credits them to the call.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

/// `inline`: as its own frame it ran the call deeper than the region top
/// `runProbe` computed (acme, 2026-10-08).
inline fn measure(call: *const fn () void, n: *const Needles) Hits {
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    return scan(n);
}

fn runProbe(label: []const u8, call: *const fn () void, n: *const Needles) !usize {
    region_hi = stackHere() - PAD;
    region_lo = region_hi - WINDOW;

    const neg = measure(callInnocent, n);
    const pos = measure(callLeaky, n);

    var total: Hits = @splat(0);
    var heap_hits: usize = 0;
    var shallowest: usize = 0;
    var deepest: usize = 0;
    for (0..5) |_| {
        for (&total, measure(call, n)) |*t, x| t.* += x;
        if (heap_view) |h| heap_hits += scanHeap(n, h);
        if (hit_min_depth != 0 and (shallowest == 0 or hit_min_depth < shallowest)) shallowest = hit_min_depth;
        if (hit_max_depth > deepest) deepest = hit_max_depth;
    }
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    const depth = dirtyDepth();

    var sum: usize = 0;
    for (total) |h| sum += h;
    var neg_sum: usize = 0;
    for (neg) |h| neg_sum += h;
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or heap_hits != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE groth16: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B heap={d} ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth, heap_hits });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<14} {d} (5 calls)\n", .{ name, total[i] });
        }
        if (sum != 0) std.debug.print("    hits {d}..{d} B below the region top\n", .{ shallowest, deepest });
    }
    try std.testing.expectEqual(@as(usize, 0), neg_sum);
    heap_view = null;
    try std.testing.expect(pos_sum >= 1); // the scan can see a parked secret
    return sum + heap_hits;
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

// ── needles ─────────────────────────────────────────────────────────────────

var nd: Needles = .{};

/// A uniformly spread field element, deterministic in `(tag, i)`.
fn bigFr(tag: u8, i: u8) Fr {
    var out: [64]u8 = undefined;
    Sha512.hash(&[_]u8{ 'g', '1', '6', tag, i }, &out, .{});
    return Fr.reduceWide(&out);
}

fn addG1(n: *Needles, name: []const u8, j: G1.Jacobian) void {
    n.addValue(name, &j.x);
    n.addValue(name, &j.y);
    n.addValue(name, &j.z);
    const a = j.toAffine();
    n.addValue(name, &a.x);
    n.addValue(name, &a.y);
    n.addBoth(name, &a.x.toBytes());
    n.addBoth(name, &a.y.toBytes());
}

fn addG2(n: *Needles, name: []const u8, j: G2.Jacobian) void {
    n.addValue(name, &j.x);
    n.addValue(name, &j.y);
    n.addValue(name, &j.z);
    const a = j.toAffine();
    n.addValue(name, &a.x);
    n.addValue(name, &a.y);
}

fn addAll(n: *Needles, name: []const u8, vs: []const Fr) void {
    for (vs) |v| n.addFr(name, v);
}

// The circuit of `harness_test.zig` (copied: that file keeps it private).
// Witness layout `[1, out1, out2, out3, x, y, xy]`, 3 public inputs.
const nt_num_vars: usize = 7;
const nt_num_public: usize = 3;
const nt_domain: usize = 4;

fn ntConstraints() [4]r1cs.Constraint {
    const one = Fr.one;
    return .{
        .{
            .a = &[_]r1cs.Term{.{ .index = 4, .coeff = one }},
            .b = &[_]r1cs.Term{.{ .index = 5, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 6, .coeff = one }},
        },
        .{
            .a = &[_]r1cs.Term{.{ .index = 4, .coeff = one }},
            .b = &[_]r1cs.Term{.{ .index = 4, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 1, .coeff = one }},
        },
        .{
            .a = &[_]r1cs.Term{.{ .index = 5, .coeff = one }},
            .b = &[_]r1cs.Term{.{ .index = 5, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 2, .coeff = one }},
        },
        .{
            .a = &[_]r1cs.Term{
                .{ .index = 1, .coeff = one },
                .{ .index = 2, .coeff = one },
                .{ .index = 6, .coeff = one },
                .{ .index = 6, .coeff = one },
            },
            .b = &[_]r1cs.Term{.{ .index = 0, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 3, .coeff = one }},
        },
    };
}

fn ntWitness(x: Fr, y: Fr) [nt_num_vars]Fr {
    const xy = x.mul(y);
    const o1 = x.mul(x);
    const o2 = y.mul(y);
    return .{ Fr.one, o1, o2, o1.add(o2).add(xy).add(xy), x, y, xy };
}

const Matrix = enum { a, b, c };

/// `col_i(τ)` as `prover.columnEvalAtTau` computes it.
fn columnEval(sys: r1cs.System, which: Matrix, wire: usize, tau: Fr) Fr {
    var evals = [_]Fr{Fr.zero} ** nt_domain;
    for (sys.constraints, 0..) |con, j| {
        const lc = switch (which) {
            .a => con.a,
            .b => con.b,
            .c => con.c,
        };
        for (lc) |t| if (t.index == wire) {
            evals[j] = evals[j].add(t.coeff);
        };
    }
    fft.intt(nt_domain, &evals);
    return poly.eval(&evals, tau);
}

fn setupNeedles(n: *Needles, tw: prover.ToxicWaste, sys: r1cs.System) void {
    n.addFr("tau", tw.tau);
    n.addFr("alpha", tw.alpha);
    n.addFr("beta", tw.beta);
    n.addFr("gamma", tw.gamma);
    n.addFr("delta", tw.delta);
    const gi = tw.gamma.inv() catch unreachable;
    const di = tw.delta.inv() catch unreachable;
    n.addFr("gamma_inv", gi);
    n.addFr("delta_inv", di);
    const z_tau = domain.Domain(nt_domain).vanishingEval(tw.tau);
    n.addFr("z_tau", z_tau);
    var tp = Fr.one;
    for (0..nt_domain - 1) |_| {
        n.addFr("tau_pow", tp);
        n.addFr("h_scalar", tp.mul(z_tau).mul(di));
        tp = tp.mul(tw.tau);
    }
    for (0..sys.num_vars) |i| {
        const ui = columnEval(sys, .a, i, tw.tau);
        const vi = columnEval(sys, .b, i, tw.tau);
        const wi = columnEval(sys, .c, i, tw.tau);
        n.addFr("u_i", ui);
        n.addFr("v_i", vi);
        n.addFr("w_i", wi);
        const combined = tw.beta.mul(ui).add(tw.alpha.mul(vi)).add(wi);
        n.addFr("combined", combined);
        n.addFr("combined/gamma", combined.mul(gi));
        n.addFr("combined/delta", combined.mul(di));
    }
}

fn randomizerNeedles(n: *Needles, rand: prover.Randomizers, delta1: G1.Affine, delta2: G2.Affine) void {
    const rs = rand.r.mul(rand.s);
    n.addFr("r", rand.r);
    n.addFr("s", rand.s);
    n.addFr("r*s", rs);
    const d1 = G1.Jacobian.fromAffine(delta1);
    const d2 = G2.Jacobian.fromAffine(delta2);
    addG1(n, "r*delta1", d1.scalarMul(rand.r));
    addG1(n, "s*delta1", d1.scalarMul(rand.s));
    addG1(n, "rs*delta1", d1.scalarMul(rs));
    addG2(n, "s*delta2", d2.scalarMul(rand.s));
}

fn proveNeedles(n: *Needles, w: []const Fr, rand: prover.Randomizers, pk: prover.ProvingKey, sys: r1cs.System) void {
    addAll(n, "witness", w);
    randomizerNeedles(n, rand, pk.delta_g1, pk.delta_g2);
    var a_ev = [_]Fr{Fr.zero} ** nt_domain;
    var b_ev = [_]Fr{Fr.zero} ** nt_domain;
    var c_ev = [_]Fr{Fr.zero} ** nt_domain;
    for (0..nt_domain) |j| {
        const e = sys.evalConstraint(j, w);
        a_ev[j] = e.a;
        b_ev[j] = e.b;
        c_ev[j] = e.c;
    }
    addAll(n, "a_ev", &a_ev);
    addAll(n, "b_ev", &b_ev);
    addAll(n, "c_ev", &c_ev);
    fft.intt(nt_domain, &a_ev);
    fft.intt(nt_domain, &b_ev);
    fft.intt(nt_domain, &c_ev);
    addAll(n, "a_coef", &a_ev);
    addAll(n, "b_coef", &b_ev);
    addAll(n, "c_coef", &c_ev);
    var ab = [_]Fr{Fr.zero} ** (2 * nt_domain - 1);
    fft.mulViaFFT(2 * nt_domain, &ab, &a_ev, &b_ev);
    var p = [_]Fr{Fr.zero} ** (2 * nt_domain - 1);
    poly.sub(&p, &ab, &c_ev);
    var h = [_]Fr{Fr.zero} ** (nt_domain - 1);
    _ = poly.divByVanishing(&h, &p, nt_domain) catch unreachable;
    addAll(n, "ab", &ab);
    addAll(n, "p", &p);
    addAll(n, "h", &h);
}

/// `zkprove.prove`'s evaluations: A·w, B·w, C = A·B on the domain, then the
/// same three on the coset and the quotient.
fn zkproveNeedles(n: *Needles, gpa: std.mem.Allocator, z: zkey.ZKey, w: []const Fr, rand: prover.Randomizers) !void {
    addAll(n, "witness", w);
    randomizerNeedles(n, rand, z.delta_g1, z.delta_g2);
    const sz: usize = z.domain_size;
    const evals = try gpa.alloc(Fr, 3 * sz);
    defer gpa.free(evals);
    @memset(evals, Fr.zero);
    const a = evals[0..sz];
    const b = evals[sz .. 2 * sz];
    const c = evals[2 * sz ..];
    for (z.coefs) |co| {
        const target = if (co.matrix == .a) a else b;
        target[co.constraint] = target[co.constraint].add(co.value.mul(w[co.signal]));
    }
    for (a, b, c) |av, bv, *cv| cv.* = av.mul(bv);
    addAll(n, "a_dom", a);
    addAll(n, "b_dom", b);
    addAll(n, "c_dom", c);
    const log_n = z.power();
    const root = domain.rootOfUnity(log_n);
    const root_inv = root.inv() catch unreachable;
    const n_inv = (Fr.fromBytes(nBytes(sz)) catch unreachable).inv() catch unreachable;
    const g = domain.rootOfUnity(log_n + 1);
    for ([_][]Fr{ a, b, c }) |v| {
        fft.ntt(v, root_inv);
        var gj = n_inv;
        for (v) |*x| {
            x.* = x.mul(gj);
            gj = gj.mul(g);
        }
        fft.ntt(v, root);
    }
    addAll(n, "a_coset", a);
    addAll(n, "b_coset", b);
    addAll(n, "c_coset", c);
    for (a, b, c) |*av, bv, cv| av.* = av.mul(bv).sub(cv);
    addAll(n, "h", a);
}

fn nBytes(sz: usize) [32]u8 {
    var out: [32]u8 = @splat(0);
    std.mem.writeInt(u64, out[24..32], sz, .big);
    return out;
}

// ── API adapter: the only place that names the shapes under test ────────────
// (BEFORE the 2026-10-09 fix these took the secrets by value.)

fn apiSetup(gpa: std.mem.Allocator, sys: r1cs.System, tw: *const prover.ToxicWaste) prover.SetupError!prover.KeyPair {
    return prover.setup(nt_domain, gpa, sys, nt_num_public, tw);
}
fn apiProve(pk: prover.ProvingKey, sys: r1cs.System, w: []const Fr, rand: *const prover.Randomizers) prover.ProveError!prover.Proof {
    return prover.prove(nt_domain, pk, sys, nt_num_public, w, rand);
}
fn apiZkProve(gpa: std.mem.Allocator, z: zkey.ZKey, w: []const Fr, rand: *const prover.Randomizers) zkprove.ProveError!zkprove.Proof {
    return zkprove.prove(gpa, z, w, rand);
}
fn apiContribute(gpa: std.mem.Allocator, z: *zkey.ZKey, x: *const Fr, s: *const Fr) !void {
    return phase2.contribute(gpa, z, x, s, "probe");
}
fn apiParseWitness(gpa: std.mem.Allocator, bytes: []const u8) ![]Fr {
    return circom.parseWitness(gpa, bytes);
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

var cur_tw: prover.ToxicWaste = undefined;
var cur_rand: prover.Randomizers = undefined;
var cur_sys: r1cs.System = undefined;
var cur_cons: [4]r1cs.Constraint = undefined;
var cur_pk: prover.ProvingKey = undefined;
var cur_wit: [nt_num_vars]Fr = undefined;
var cur_z: zkey.ZKey = undefined; // proved against
var cur_zw: [6]Fr = undefined;
var cur_cz: zkey.ZKey = undefined; // contributed to
var cur_x: Fr = undefined;
var cur_s: Fr = undefined;
var cur_wtns: [512]u8 = undefined;
var cur_wtns_len: usize = 0;

var heap_buf: [256 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;

fn freshHeap() std.mem.Allocator {
    @memset(&heap_buf, 0);
    heap_fba = .init(&heap_buf);
    return heap_fba.allocator();
}

noinline fn callSetup() void {
    const kp = apiSetup(freshHeap(), cur_sys, &cur_tw) catch unreachable;
    std.mem.doNotOptimizeAway(&kp);
}
noinline fn callProve() void {
    const proof = apiProve(cur_pk, cur_sys, &cur_wit, &cur_rand) catch unreachable;
    std.mem.doNotOptimizeAway(&proof);
}
noinline fn callZkProve() void {
    const proof = apiZkProve(freshHeap(), cur_z, &cur_zw, &cur_rand) catch unreachable;
    std.mem.doNotOptimizeAway(&proof);
}
noinline fn callContribute() void {
    apiContribute(std.testing.allocator, &cur_cz, &cur_x, &cur_s) catch unreachable;
}
noinline fn callParseWitness() void {
    const w = apiParseWitness(freshHeap(), cur_wtns[0..cur_wtns_len]) catch unreachable;
    std.mem.doNotOptimizeAway(w.ptr);
}

test "STACKPROBE: no prover-secret residue on the dead stack after setup, prove, zkprove, contribute and parseWitness" {
    try skipUnlessOptimized();
    const gpa = std.testing.allocator;
    cur_z = try zkey.parse(gpa, t1_zkey);
    defer cur_z.deinit(gpa);
    cur_cz = try zkey.parse(gpa, t1_zkey);
    defer cur_cz.deinit(gpa);
    cur_cons = ntConstraints();
    cur_sys = .{ .num_vars = nt_num_vars, .constraints = &cur_cons };

    var bad: usize = 0;
    for (0..2) |ci| {
        const c: u8 = @intCast(ci);
        cur_tw = .{ .tau = bigFr(1, c), .alpha = bigFr(2, c), .beta = bigFr(3, c), .gamma = bigFr(4, c), .delta = bigFr(5, c) };
        cur_rand = .{ .r = bigFr(6, c), .s = bigFr(7, c) };
        cur_wit = ntWitness(bigFr(8, c), bigFr(9, c));
        for (&cur_zw, 0..) |*v, i| v.* = bigFr(10 + c, @intCast(i));
        cur_x = bigFr(12, c);
        cur_s = bigFr(13, c);

        // setup: the toxic waste and everything derived from it.
        nd.reset();
        setupNeedles(&nd, cur_tw, cur_sys);
        nd.sort();
        leak_src = cur_tw.tau.toBytes();
        bad += try runProbe("prover.setup", callSetup, &nd);

        // prove: witness, r, s, the quotient, r*delta terms.
        const kp = try apiSetup(gpa, cur_sys, &cur_tw);
        defer prover.freeKeyPair(gpa, kp);
        cur_pk = kp.pk;
        nd.reset();
        proveNeedles(&nd, &cur_wit, cur_rand, cur_pk, cur_sys);
        nd.sort();
        leak_src = cur_wit[4].toBytes();
        bad += try runProbe("prover.prove", callProve, &nd);

        // zkprove: also the heap its evaluations and MSM scratch used.
        nd.reset();
        try zkproveNeedles(&nd, gpa, cur_z, &cur_zw, cur_rand);
        nd.sort();
        leak_src = cur_zw[1].toBytes();
        heap_view = &heap_buf;
        bad += try runProbe("zkprove.prove", callZkProve, &nd);

        // phase2.contribute: x, s, x^-1, s*x.
        nd.reset();
        nd.addFr("x", cur_x);
        nd.addFr("s", cur_s);
        nd.addFr("x_inv", cur_x.inv() catch unreachable);
        nd.addFr("s*x", cur_s.mul(cur_x));
        nd.sort();
        leak_src = cur_x.toBytes();
        bad += try runProbe("phase2.contribute", callContribute, &nd);

        // circom.parseWitness: the decoded witness.
        var aw: std.Io.Writer = .fixed(&cur_wtns);
        try circom.writeWitness(&aw, &cur_zw);
        cur_wtns_len = aw.end;
        nd.reset();
        addAll(&nd, "witness", &cur_zw);
        nd.sort();
        leak_src = cur_zw[1].toBytes();
        bad += try runProbe("circom.parseWitness", callParseWitness, &nd);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

const t1_zkey = @embedFile("testdata/snarkjs/t1.zkey");
