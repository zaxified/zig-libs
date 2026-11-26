// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every secret path of the module:
//! `deriveKeyPair`, `scalarFromWideBytes`, `blind`, `blindEvaluate`,
//! `finalize`, `evaluate`, the VOPRF and POPRF server/client calls (DLEQ proof
//! nonce included) and `evaluatePoprf`. Kept in the module per
//! `CONVENTIONS.md` §9.
//!
//! Engine as `hpke`'s probe (form): the measured region is
//! addressed directly `PAD` below the probe and the call runs under a
//! `PAD`-deep `shim`. ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe
//! fill `undefined` with 0xaa.
//!
//! Needles are every 16-byte window of every image a secret is held in: seed,
//! server key, blind scalar and its inverse, the unblinded element, the PRF
//! output, the DLEQ nonce and `r - c*k`'s intermediate `c*k`, the POPRF
//! tweaked scalar `t` and its inverse, the client input.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a key in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const voprf = @import("root.zig");
const compat = @import("test_shim.zig");
const ct25519 = @import("ct25519");
const scalar = voprf.Ristretto255.scalar;
const Element = voprf.Element;

// ── engine (as hpke/p256 probes form) ──
const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 8192;

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
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    fn lookupName(self: *Needles, name: []const u8) usize {
        for (self.names[0..self.n_names], 0..) |n, i| if (std.mem.eql(u8, n, name)) return i;
        self.names[self.n_names] = name;
        self.n_names += 1;
        return self.n_names - 1;
    }

    /// The image and its byte reversal (a big-endian value is often held
    /// little-endian, and the reverse).
    fn addBytes(self: *Needles, name: []const u8, b: []const u8) void {
        self.addImage(name, b);
        var r: [256]u8 = undefined;
        @memcpy(r[0..b.len], b);
        std.mem.reverse(u8, r[0..b.len]);
        self.addImage(name, r[0..b.len]);
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
// frames (a wrapper's by-value copies) are seen. The earlier form claimed an
// uninitialised buffer at the call's depth instead, and the claiming frame's
// own header and locals hid the top few hundred bytes (a stale
// negative-control hit there, and a positive control that went blind when
// the scan function grew a local).
const PAD = 2048;

var region_lo: usize = 0;
var region_hi: usize = 0;
var snap: [WINDOW]u8 = undefined;

/// An address inside a frame called from the probe — below the probe's
/// own frame, at the depth `paint`/`shim`/`snapshot` start at.
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

/// Count needle windows in the last snapshot, one per run of overlapping
/// windows. `hit_min_depth`/`hit_max_depth`: bytes below the region's top.
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

/// How deep the last call's frames reached below the region's top.
fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
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
/// spills them into its frame, where the scan credits them to the call
/// (a negative-control "hit" of `x mod q` between two saved stack
/// pointers in `callInnocent`'s frame, gone when the setup code changed). The
/// compiler saves and restores the probe's own values around the asm.
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
/// `runProbe` computed.
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
    var shallowest: usize = 0;
    var deepest: usize = 0;
    for (0..5) |_| {
        for (&total, measure(call, n)) |*t, x| t.* += x;
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
    // Summed over every needle: images that share a window (a scalar and its
    // zero-extended form) report a hit under whichever name sorts first.
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE voprf: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<10} {d} (5 calls)\n", .{ name, total[i] });
        }
        if (sum != 0) std.debug.print("    hits {d}..{d} B below the region top\n", .{ shallowest, deepest });
    }
    try std.testing.expectEqual(@as(usize, 0), neg_sum);
    try std.testing.expect(pos_sum >= 1); // the scan can see a parked secret
    residueCheck(label);
    return sum;
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
}

/// Audit-local deterministic byte strings: hashes of a label, so no 16-byte
/// window of them is a run of zeros or of paint that a dead stack holds anyway.
fn seedBytes(comptime N: usize, label: []const u8, i: u8) [N]u8 {
    var out: [N]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha512.init(.{});
    h.update(label);
    h.update(&[_]u8{i});
    var d: [64]u8 = undefined;
    h.final(&d);
    var o: usize = 0;
    var ctr: u8 = 0;
    while (o < N) : (ctr += 1) {
        var hh = std.crypto.hash.sha2.Sha512.init(.{});
        hh.update(&d);
        hh.update(&[_]u8{ctr});
        var blk: [64]u8 = undefined;
        hh.final(&blk);
        const k = @min(64, N - o);
        @memcpy(out[o..][0..k], blk[0..k]);
        o += k;
    }
    return out;
}

// ── fixtures ────────────────────────────────────────────────────────────────

const password = "correct horse battery staple, probe";
const info = "voprf dead-stack probe info";
const n_cases = 2;

var seed: [32]u8 = undefined;
var sk: [32]u8 = undefined;
var pk: Element = undefined;
var blind_s: [32]u8 = undefined;
var proof_r: [32]u8 = undefined;
var wide: [64]u8 = undefined;
var blinded: Element = undefined;
var evaluated: Element = undefined;
var evaluated_v: voprf.VerifiableEvaluation = undefined;
var blinded_p: voprf.PoprfBlindResult = undefined;
var evaluated_p: voprf.VerifiableEvaluation = undefined;

var kp_sink: voprf.KeyPair = undefined;
var scalar_sink: [32]u8 = undefined;
var out_sink: [64]u8 = undefined;
var el_sink: Element = undefined;
var proof_sink: voprf.Proof = undefined;
var ve_sink: voprf.VerifiableEvaluation = undefined;
var pb_sink: voprf.PoprfBlindResult = undefined;

// ADAPTER: the only block that depends on the call shapes of the module API.
noinline fn callDerive() void {
    voprf.deriveKeyPair(.voprf, &seed, info, &kp_sink) catch unreachable;
}
noinline fn callWide() void {
    voprf.scalarFromWideBytes(&wide, &scalar_sink);
}
noinline fn callBlind() void {
    el_sink = voprf.blind(.oprf, password, &blind_s) catch unreachable;
}
noinline fn callBlindEvaluate() void {
    el_sink = voprf.blindEvaluate(&sk, blinded);
}
noinline fn callFinalize() void {
    voprf.finalize(password, &blind_s, evaluated, &out_sink) catch unreachable;
}
noinline fn callEvaluate() void {
    voprf.evaluate(.oprf, &sk, password, &out_sink) catch unreachable;
}
noinline fn callGenerateProof() void {
    proof_sink = voprf.generateProof(.voprf, &sk, Element.generator, pk, &.{blinded}, &.{evaluated}, &proof_r) catch unreachable;
}
noinline fn callBlindEvaluateVerifiable() void {
    ve_sink = voprf.blindEvaluateVerifiable(&sk, pk, blinded, &proof_r) catch unreachable;
}
noinline fn callFinalizeVerifiable() void {
    voprf.finalizeVerifiable(password, &blind_s, evaluated_v.evaluated_element, blinded, pk, evaluated_v.proof, &out_sink) catch unreachable;
}
noinline fn callBlindPoprf() void {
    pb_sink = voprf.blindPoprf(password, info, pk, &blind_s) catch unreachable;
}
noinline fn callBlindEvaluatePoprf() void {
    ve_sink = voprf.blindEvaluatePoprf(&sk, blinded_p.blinded_element, info, &proof_r) catch unreachable;
}
noinline fn callFinalizePoprf() void {
    voprf.finalizePoprf(password, &blind_s, evaluated_p.evaluated_element, blinded_p.blinded_element, evaluated_p.proof, info, blinded_p.tweaked_key, &out_sink) catch unreachable;
}
noinline fn callEvaluatePoprf() void {
    voprf.evaluatePoprf(&sk, password, info, &out_sink) catch unreachable;
}
// END ADAPTER

fn setUp(ci: u8) !void {
    seed = seedBytes(32, "voprf-seed", ci);
    const kp = try compat.deriveKeyPair(.voprf, seed, info);
    sk = kp.sk;
    pk = kp.pk;
    wide = seedBytes(64, "voprf-wide", ci);
    blind_s = compat.scalarFromWideBytes(wide);
    proof_r = compat.scalarFromWideBytes(seedBytes(64, "voprf-r", ci));
    leak_src = sk;
    blinded = try compat.blind(.voprf, password, blind_s);
    evaluated = compat.blindEvaluate(sk, blinded);
    evaluated_v = try compat.blindEvaluateVerifiable(sk, pk, blinded, proof_r);
    blinded_p = try compat.blindPoprf(password, info, pk, blind_s);
    evaluated_p = try compat.blindEvaluatePoprf(sk, blinded_p.blinded_element, info, proof_r);
}

fn invOf(s: [32]u8) [32]u8 {
    return scalar.Scalar.fromBytes(s).invert().toBytes();
}

const H = struct {
    fn hashed(mode: voprf.Mode) Element {
        return switch (mode) {
            .oprf => voprf.hashToGroup(.oprf, password) catch unreachable,
            .voprf => voprf.hashToGroup(.voprf, password) catch unreachable,
            .poprf => voprf.hashToGroup(.poprf, password) catch unreachable,
        };
    }
};

fn addCommon(n: *Needles) void {
    n.addBytes("control", &leak_src);
}

test "STACKPROBE: no key, blind or nonce residue on the dead stack (voprf)" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        var n: Needles = .{};

        // deriveKeyPair: seed, the 64-byte uniform string, the key.
        n = .{};
        n.addBytes("seed", &seed);
        n.addBytes("sk", &sk);
        const dst = comptime "DeriveKeyPair" ++ voprf.contextString(.voprf);
        var info_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &info_len, info.len, .big);
        n.addBytes("wide", &voprf.expandMessageXmd(64, &.{ &seed, &info_len, info, &[1]u8{0} }, dst));
        addCommon(&n);
        n.sort();
        bad += try runProbe("deriveKeyPair", callDerive, &n);

        // scalarFromWideBytes: the wide string and the scalar.
        n = .{};
        n.addBytes("wide", &wide);
        n.addBytes("blind", &blind_s);
        addCommon(&n);
        n.sort();
        bad += try runProbe("scalarFromWideBytes", callWide, &n);

        // blind (OPRF): blind scalar and the password.
        n = .{};
        n.addBytes("blind", &blind_s);
        n.addBytes("password", password);
        addCommon(&n);
        n.sort();
        bad += try runProbe("blind", callBlind, &n);

        // blindEvaluate: server key.
        n = .{};
        n.addBytes("sk", &sk);
        addCommon(&n);
        n.sort();
        bad += try runProbe("blindEvaluate", callBlindEvaluate, &n);

        // finalize: blind, inverse, unblinded element, output, password.
        const unb = ct25519.mulRistretto(evaluated.p, invOf(blind_s)).toBytes();
        var out_oprf: [64]u8 = undefined;
        out_oprf = compat.finalize(password, blind_s, evaluated) catch unreachable;
        n = .{};
        n.addBytes("blind", &blind_s);
        n.addBytes("blind^-1", &invOf(blind_s));
        n.addBytes("unblinded", &unb);
        n.addBytes("output", &out_oprf);
        n.addBytes("password", password);
        addCommon(&n);
        n.sort();
        bad += try runProbe("finalize", callFinalize, &n);

        // evaluate: key, N = sk*H(x), output.
        const nn = ct25519.mulRistretto(H.hashed(.oprf).p, sk).toBytes();
        n = .{};
        n.addBytes("sk", &sk);
        n.addBytes("unblinded", &nn);
        n.addBytes("password", password);
        n.addBytes("output", &(compat.evaluate(.oprf, sk, password) catch unreachable));
        addCommon(&n);
        n.sort();
        bad += try runProbe("evaluate", callEvaluate, &n);

        // generateProof / VOPRF server: key, nonce, c*k.
        const prf = evaluated_v.proof;
        n = .{};
        n.addBytes("sk", &sk);
        n.addBytes("proof_r", &proof_r);
        n.addBytes("c*k", &scalar.mul(prf.c, sk));
        addCommon(&n);
        n.sort();
        bad += try runProbe("generateProof", callGenerateProof, &n);
        bad += try runProbe("blindEvaluateVerifiable", callBlindEvaluateVerifiable, &n);

        // finalizeVerifiable: as finalize.
        var out_v: [64]u8 = undefined;
        out_v = compat.finalize(password, blind_s, evaluated_v.evaluated_element) catch unreachable;
        n = .{};
        n.addBytes("blind", &blind_s);
        n.addBytes("blind^-1", &invOf(blind_s));
        n.addBytes("unblinded", &ct25519.mulRistretto(evaluated_v.evaluated_element.p, invOf(blind_s)).toBytes());
        n.addBytes("output", &out_v);
        n.addBytes("password", password);
        addCommon(&n);
        n.sort();
        bad += try runProbe("finalizeVerifiable", callFinalizeVerifiable, &n);

        // blindPoprf: blind scalar, password.
        n = .{};
        n.addBytes("blind", &blind_s);
        n.addBytes("password", password);
        addCommon(&n);
        n.sort();
        bad += try runProbe("blindPoprf", callBlindPoprf, &n);

        // blindEvaluatePoprf: key, t = sk + m, 1/t, nonce.
        const m = voprf.hashToScalar(.poprf, &.{ "Info", &info_len, info });
        const t = scalar.add(sk, m);
        const prf_p = evaluated_p.proof;
        n = .{};
        n.addBytes("sk", &sk);
        n.addBytes("t", &t);
        n.addBytes("t^-1", &invOf(t));
        n.addBytes("proof_r", &proof_r);
        n.addBytes("c*t", &scalar.mul(prf_p.c, t));
        addCommon(&n);
        n.sort();
        bad += try runProbe("blindEvaluatePoprf", callBlindEvaluatePoprf, &n);

        // finalizePoprf: blind, 1/blind, unblinded, output.
        var out_p: [64]u8 = undefined;
        out_p = compat.finalizePoprfUnverified(password, blind_s, evaluated_p.evaluated_element, info) catch unreachable;
        n = .{};
        n.addBytes("blind", &blind_s);
        n.addBytes("blind^-1", &invOf(blind_s));
        n.addBytes("unblinded", &ct25519.mulRistretto(evaluated_p.evaluated_element.p, invOf(blind_s)).toBytes());
        n.addBytes("output", &out_p);
        n.addBytes("password", password);
        addCommon(&n);
        n.sort();
        bad += try runProbe("finalizePoprf", callFinalizePoprf, &n);

        // evaluatePoprf: key, t, 1/t, N, output.
        const np = ct25519.mulRistretto(H.hashed(.poprf).p, invOf(t)).toBytes();
        n = .{};
        n.addBytes("sk", &sk);
        n.addBytes("t", &t);
        n.addBytes("t^-1", &invOf(t));
        n.addBytes("unblinded", &np);
        n.addBytes("password", password);
        n.addBytes("output", &(compat.evaluatePoprf(sk, password, info) catch unreachable));
        addCommon(&n);
        n.sort();
        bad += try runProbe("evaluatePoprf", callEvaluatePoprf, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

// ── the other four suites ───────────────────────────────────────────────────
//
// The same engine over `Suite(cs)`'s secret paths. Needles are the byte images
// the API itself hands out or takes (seed, key, blind, proof nonce, the wide
// string, the outputs, the password); the group-internal intermediates the
// ristretto255 probe also lists (`blind^-1`, the unblinded element) are not
// computed here: their encodings are the sibling curves' internals.

fn SuiteProbe(comptime cs: voprf.Ciphersuite) type {
    return struct {
        const S = voprf.Suite(cs);
        var s_seed: [32]u8 = undefined;
        var s_sk: [S.Ns]u8 = undefined;
        var s_pk: S.Element = undefined;
        var s_wide: [S.wide_length]u8 = undefined;
        var s_blind: [S.Ns]u8 = undefined;
        var s_r: [S.Ns]u8 = undefined;
        var s_blinded: S.Element = undefined;
        var s_evaluated: S.Element = undefined;

        var s_kp_sink: S.KeyPair = undefined;
        var s_scalar_sink: [S.Ns]u8 = undefined;
        var s_el_sink: S.Element = undefined;
        var s_out_sink: [S.Nh]u8 = undefined;
        var s_ve_sink: S.VerifiableEvaluation = undefined;

        noinline fn sCallDerive() void {
            S.deriveKeyPair(.voprf, &s_seed, info, &s_kp_sink) catch unreachable;
        }
        noinline fn sCallWide() void {
            S.scalarFromWideBytes(&s_wide, &s_scalar_sink);
        }
        noinline fn sCallBlind() void {
            s_el_sink = S.blind(.oprf, password, &s_blind) catch unreachable;
        }
        noinline fn sCallBlindEvaluate() void {
            s_el_sink = S.blindEvaluate(&s_sk, s_blinded);
        }
        noinline fn sCallFinalize() void {
            S.finalize(password, &s_blind, s_evaluated, &s_out_sink) catch unreachable;
        }
        noinline fn sCallEvaluate() void {
            S.evaluate(.oprf, &s_sk, password, &s_out_sink) catch unreachable;
        }
        noinline fn sCallBlindEvaluateVerifiable() void {
            s_ve_sink = S.blindEvaluateVerifiable(&s_sk, s_pk, s_blinded, &s_r) catch unreachable;
        }
        noinline fn sCallEvaluatePoprf() void {
            S.evaluatePoprf(&s_sk, password, info, &s_out_sink) catch unreachable;
        }

        fn run(ci: u8) !usize {
            const label = @tagName(cs);
            s_seed = seedBytes(32, label ++ "-seed", ci);
            var kp: S.KeyPair = undefined;
            try S.deriveKeyPair(.voprf, &s_seed, info, &kp);
            s_sk = kp.sk;
            s_pk = kp.pk;
            s_wide = seedBytes(S.wide_length, label ++ "-wide", ci);
            S.scalarFromWideBytes(&s_wide, &s_blind);
            S.scalarFromWideBytes(&seedBytes(S.wide_length, label ++ "-r", ci), &s_r);
            leak_src = s_sk[0..LEAK].*;
            s_blinded = try S.blind(.oprf, password, &s_blind);
            s_evaluated = S.blindEvaluate(&s_sk, s_blinded);
            var out_fin: [S.Nh]u8 = undefined;
            try S.finalize(password, &s_blind, s_evaluated, &out_fin);
            var out_eval: [S.Nh]u8 = undefined;
            try S.evaluate(.oprf, &s_sk, password, &out_eval);
            var out_poprf: [S.Nh]u8 = undefined;
            try S.evaluatePoprf(&s_sk, password, info, &out_poprf);

            var bad: usize = 0;
            var n: Needles = .{};
            n.addBytes("seed", &s_seed);
            n.addBytes("sk", &s_sk);
            addCommon(&n);
            n.sort();
            bad += try runProbe(label ++ ".deriveKeyPair", sCallDerive, &n);

            n = .{};
            n.addBytes("wide", &s_wide);
            n.addBytes("blind", &s_blind);
            addCommon(&n);
            n.sort();
            bad += try runProbe(label ++ ".scalarFromWideBytes", sCallWide, &n);

            n = .{};
            n.addBytes("blind", &s_blind);
            n.addBytes("password", password);
            addCommon(&n);
            n.sort();
            bad += try runProbe(label ++ ".blind", sCallBlind, &n);

            n = .{};
            n.addBytes("sk", &s_sk);
            addCommon(&n);
            n.sort();
            bad += try runProbe(label ++ ".blindEvaluate", sCallBlindEvaluate, &n);

            n = .{};
            n.addBytes("blind", &s_blind);
            n.addBytes("output", &out_fin);
            n.addBytes("password", password);
            addCommon(&n);
            n.sort();
            bad += try runProbe(label ++ ".finalize", sCallFinalize, &n);

            n = .{};
            n.addBytes("sk", &s_sk);
            n.addBytes("output", &out_eval);
            n.addBytes("password", password);
            addCommon(&n);
            n.sort();
            bad += try runProbe(label ++ ".evaluate", sCallEvaluate, &n);

            n = .{};
            n.addBytes("sk", &s_sk);
            n.addBytes("proof_r", &s_r);
            addCommon(&n);
            n.sort();
            bad += try runProbe(label ++ ".blindEvaluateVerifiable", sCallBlindEvaluateVerifiable, &n);

            n = .{};
            n.addBytes("sk", &s_sk);
            n.addBytes("output", &out_poprf);
            n.addBytes("password", password);
            addCommon(&n);
            n.sort();
            bad += try runProbe(label ++ ".evaluatePoprf", sCallEvaluatePoprf, &n);
            return bad;
        }
    };
}

test "STACKPROBE: no key, blind or nonce residue on the dead stack (decaf448, P-256, P-384, P-521 suites)" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        inline for (.{ .decaf448_shake256, .p256_sha256, .p384_sha384, .p521_sha512 }) |cs| {
            bad += try SuiteProbe(cs).run(@intCast(ci));
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

var oprf_server_sink: voprf.OprfServer = undefined;
noinline fn callServerDeriveInto() void {
    voprf.OprfServer.deriveInto(&oprf_server_sink, &seed, info) catch unreachable;
}

// `derive` is not probed: it returns the key by value, and that copy of its own result sits in its
// frame above any burn (the caller holds it, as with bip32 `neuter`); `deriveInto` is the
// out-pointer form with no such copy.
test "mutation 2026-11-25: STACKPROBE: OprfServer.deriveInto leaves no server-key residue on the dead stack" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        // The OPRF-mode server key (a different key from the VOPRF `sk` of setUp).
        const server = try voprf.OprfServer.derive(&seed, info);
        var n: Needles = .{};
        n.addBytes("seed", &seed);
        n.addBytes("server sk", &server.sk);
        const dst = comptime "DeriveKeyPair" ++ voprf.contextString(.oprf);
        var info_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &info_len, info.len, .big);
        n.addBytes("wide", &voprf.expandMessageXmd(64, &.{ &seed, &info_len, info, &[1]u8{0} }, dst));
        addCommon(&n);
        n.sort();
        bad += try runProbe("OprfServer.deriveInto", callServerDeriveInto, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

// ── residue rule (`testkit.stackprobe.residueOf`, 2026-11-23) ───────────────
//
// The needles above are a model of the secrets. The shared engine's residue
// rule needs none: in a snapshot with a burn (the longest zero run, at least
// 512 B), a byte deeper than the burn's top that is neither zero nor paint is
// a frame the burn did not reach, whatever it held. It runs over this probe's
// own snapshot after every measured call (`runProbe`, on the snapshot of the last call), so no call is re-run
// (protocol rounds cannot be). Origin: falcon, 2026-11-23 — a keygen burn cut
// to 4 KiB passed the needle probe and failed this rule. A snapshot without
// such a run (a call that does not burn) is not judged. Failures print here
// and are asserted by the last test in this file.
var residue_failures: usize = 0;
fn residueCheck(label: []const u8) void {
    const r = @import("testkit").stackprobe.residueOf(&snap, 0xC7, 512);
    // Burn presence (2026-11-26): a snapshot with no zero run is "not judged" by the residue rule, so a
    // removed entry-point burn passed this probe unless a named needle survived (dtls 1.3, whole-module
    // mutation run). Every measured call must burn.
    if (r.burn_len == 0) {
        residue_failures += 1;
        std.debug.print("\n=== STACKPROBE burn missing ({t}): {s}: no zero run of the minimum burn length in the snapshot ===\n", .{ builtin.mode, label });
        return;
    }
    if (r.residue_bytes == 0) return;
    residue_failures += 1;
    std.debug.print("\n=== STACKPROBE residue rule ({t}): {s}: {d} B below the burn (burn {d} B from {d} B, deepest {d} B) ===\n", .{ builtin.mode, label, r.residue_bytes, r.burn_len, r.burn_top, r.residue_deepest });
}

test "STACKPROBE residue rule: no measured call left a frame below its burn" {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
    try std.testing.expectEqual(@as(usize, 0), residue_failures);
}
