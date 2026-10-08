// SPDX-License-Identifier: MIT

//! Dead-stack (and heap) residue probe for every Coconut entry point that
//! holds a secret: `keygen` (the master `(x, y_1..y_q)`, every Shamir share
//! and every polynomial coefficient), `VerificationKey.fromSecret` /
//! `VerificationKeyShare.fromShare` (the key scalars), `psSignWithSecret` and
//! `signPartial` (the key scalars, the attribute vector and the signing
//! exponent `x + sum m_i y_i`) and `proveCredential` (the attribute vector,
//! `r'`, `r`, `r~` and every `m~_j`). Kept in the module per
//! `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only: Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in. The
//! randomness is known: the calls draw through the seeded `std.Random` path
//! (`keygenSeededForTest`, `proveCredentialSeededForTest`) over a PRNG the
//! probe replays, so the coefficients, `r'`, `r`, `r~`, `m~_j` are recomputed
//! exactly. The heap the key generator and the prover used is scanned after
//! the call too (the `ys` slices are wiped by `deinit`; the polynomials and
//! `m~` by the call itself).
//!
//! Not built: the module has no blind issuance (no ElGamal key, no blinding
//! factors, no unblinding; SPEC "Backlog / deferred"), and the `Entropy.io`
//! arm is not probed (it differs from the seeded arm only in `Fr.random`,
//! which `bls12_381` already swept).
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const bls = @import("bls12_381");
const keys = @import("keys.zig");
const cred = @import("credential.zig");
const params_mod = @import("params.zig");

const g1 = bls.g1;
const g2 = bls.g2;
const Fr = bls.Fr;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;

const WINDOW = 512 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 16384;

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

    /// A G1 point: its in-memory (affine Fp limbs) image and its compressed
    /// encoding.
    fn addG1(self: *Needles, name: []const u8, p: g1.Affine) void {
        self.addImage(name, std.mem.asBytes(&p));
        self.addBoth(name, &g1.toBytesCompressed(p));
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
        std.debug.print("\n=== STACKPROBE coconut: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B heap={d} ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth, heap_hits });
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

// ── API adapter: the only place that names the shapes under test ────────────
// (BEFORE the 2026-10-09 fix these took and returned the secrets by value;
// the pre-fix numbers are in CHANGELOG.)

const Q = 4; // attributes
const T = 2;
const N = 3;
const disclosed_mask = [Q]bool{ true, false, true, false };

fn apiKeygen(out: *keys.ThresholdKeys, a: std.mem.Allocator, random: std.Random) void {
    keys.keygenSeededForTest(out, a, random, Q, T, N) catch unreachable;
}
fn apiScalar(random: std.Random) Fr {
    var f: Fr = undefined;
    (keys.Entropy{ .seeded_for_test = random }).scalar(&f);
    return f;
}
fn apiFromSecret(a: std.mem.Allocator, sk: *const keys.SecretKey) keys.VerificationKey {
    return keys.VerificationKey.fromSecret(a, sk) catch unreachable;
}
fn apiFromShare(a: std.mem.Allocator, sh: *const keys.SecretKeyShare) keys.VerificationKeyShare {
    return keys.VerificationKeyShare.fromShare(a, sh) catch unreachable;
}
fn apiSigningExponent(sk: *const keys.SecretKey, attrs: []const Fr) Fr {
    var e: Fr = undefined;
    cred.signingExponent(&e, sk, attrs);
    return e;
}
fn apiPsSign(sk: *const keys.SecretKey, h: g1.Affine, attrs: []const Fr) cred.Credential {
    return cred.psSignWithSecret(sk, h, attrs);
}
fn apiSignPartial(sh: *const keys.SecretKeyShare, h: g1.Affine, attrs: []const Fr) cred.PartialCredential {
    return cred.signPartial(sh, h, attrs) catch unreachable;
}
fn apiProve(a: std.mem.Allocator, random: std.Random, p: params_mod.Parameters, vk: keys.VerificationKey, c: cred.Credential, attrs: []const Fr) cred.ShowProof {
    return cred.proveCredentialSeededForTest(a, random, p, vk, c, attrs, &disclosed_mask, "probe") catch unreachable;
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

var nd: Needles = .{};
var cur_keys: keys.ThresholdKeys = undefined;
var cur_params: params_mod.Parameters = undefined;
var cur_attrs: [Q]Fr = undefined;
var cur_h: g1.Affine = undefined;
var cur_cred: cred.Credential = undefined;
var cur_seed: u64 = 0;
var call_prng: std.Random.DefaultPrng = undefined;

var kk_sink: keys.ThresholdKeys = undefined;
var vk_sink: keys.VerificationKey = undefined;
var vks_sink: keys.VerificationKeyShare = undefined;
var cred_sink: cred.Credential = undefined;
var partial_sink: cred.PartialCredential = undefined;
var proof_sink: cred.ShowProof = undefined;

var heap_buf: [256 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;

fn freshHeap() std.mem.Allocator {
    @memset(&heap_buf, 0);
    heap_fba = .init(&heap_buf);
    return heap_fba.allocator();
}

noinline fn callKeygen() void {
    const a = freshHeap();
    call_prng = .init(cur_seed);
    apiKeygen(&kk_sink, a, call_prng.random());
    kk_sink.deinit(a);
}
noinline fn callFromSecret() void {
    const a = freshHeap();
    vk_sink = apiFromSecret(a, &cur_keys.master_sk);
    vk_sink.deinit(a);
}
noinline fn callFromShare() void {
    const a = freshHeap();
    vks_sink = apiFromShare(a, &cur_keys.sk_shares[1]);
    vks_sink.deinit(a);
}
noinline fn callPsSign() void {
    cred_sink = apiPsSign(&cur_keys.master_sk, cur_h, &cur_attrs);
    std.mem.doNotOptimizeAway(&cred_sink);
}
noinline fn callSignPartial() void {
    partial_sink = apiSignPartial(&cur_keys.sk_shares[1], cur_h, &cur_attrs);
    std.mem.doNotOptimizeAway(&partial_sink);
}
noinline fn callProve() void {
    const a = freshHeap();
    call_prng = .init(cur_seed + 1000);
    proof_sink = apiProve(a, call_prng.random(), cur_params, cur_keys.master_vk, cur_cred, &cur_attrs);
    proof_sink.deinit(a);
}

fn frFrom(label: []const u8, ci: usize, i: usize) Fr {
    var h = Sha512.init(.{});
    h.update(label);
    h.update(&[_]u8{ @intCast(ci), @intCast(i) });
    var d: [64]u8 = undefined;
    h.final(&d);
    return Fr.reduceWide(&d);
}

/// The scalars a seeded generator hands out, in order.
fn replay(n: *Needles, name: []const u8, seed: u64, count: usize) void {
    var prng = std.Random.DefaultPrng.init(seed);
    for (0..count) |_| n.addFr(name, apiScalar(prng.random()));
}

fn addKeyNeedles(n: *Needles) void {
    n.addFr("x", cur_keys.master_sk.x);
    for (cur_keys.master_sk.ys) |y| n.addFr("y", y);
    for (cur_keys.sk_shares) |s| {
        n.addFr("share x", s.x);
        for (s.ys) |y| n.addFr("share y", y);
    }
}

test "STACKPROBE: no key, share, attribute or witness residue on the dead stack or heap after Coconut" {
    try skipUnlessOptimized();
    const gpa = std.testing.allocator;
    var bad: usize = 0;
    for (0..2) |ci| {
        cur_seed = 0xC0C0_0000 + ci;
        {
            var prng = std.Random.DefaultPrng.init(cur_seed);
            apiKeygen(&cur_keys, gpa, prng.random());
        }
        defer cur_keys.deinit(gpa);
        cur_params = try params_mod.Parameters.generate(gpa, Q);
        defer cur_params.deinit(gpa);
        for (&cur_attrs, 0..) |*m, i| m.* = frFrom("coconut-attr", ci, i);
        cur_h = cur_params.commonBase(&cur_attrs);
        cur_cred = apiPsSign(&cur_keys.master_sk, cur_h, &cur_attrs);

        // keygen: the master key, the shares, the Shamir coefficients.
        nd.reset();
        addKeyNeedles(&nd);
        replay(&nd, "coefficient", cur_seed, (Q + 1) * T);
        nd.sort();
        leak_src = cur_keys.master_sk.x.toBytes();
        heap_view = &heap_buf;
        bad += try runProbe("keygen", callKeygen, &nd);

        nd.reset();
        addKeyNeedles(&nd);
        nd.sort();
        bad += try runProbe("fromSecret", callFromSecret, &nd);
        bad += try runProbe("fromShare", callFromShare, &nd);

        // the signing side: key, attributes and the exponent between them
        nd.reset();
        addKeyNeedles(&nd);
        for (cur_attrs) |m| nd.addFr("attr", m);
        nd.addFr("e", apiSigningExponent(&cur_keys.master_sk, &cur_attrs));
        nd.sort();
        bad += try runProbe("psSignWithSecret", callPsSign, &nd);

        nd.reset();
        addKeyNeedles(&nd);
        for (cur_attrs) |m| nd.addFr("attr", m);
        const sh = &cur_keys.sk_shares[1];
        const as_sk = keys.SecretKey{ .x = sh.x, .ys = sh.ys };
        nd.addFr("e", apiSigningExponent(&as_sk, &cur_attrs));
        nd.sort();
        bad += try runProbe("signPartial", callSignPartial, &nd);

        // the show: attributes, r', r, r~ and the hidden m~_j
        nd.reset();
        // Only the HIDDEN attributes are secret here: the disclosed ones go
        // to the verifier in the clear (and through `disclosed_values`).
        for (cur_attrs, disclosed_mask) |m, d| if (!d) nd.addFr("hidden attr", m);
        replay(&nd, "witness", cur_seed + 1000, 3 + 2);
        nd.sort();
        leak_src = cur_attrs[1].toBytes(); // hidden
        heap_view = &heap_buf;
        bad += try runProbe("proveCredential", callProve, &nd);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
