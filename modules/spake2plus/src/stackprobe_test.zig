// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every secret path of the module: `computeW0W1`,
//! `computeL`, `proverStart`, `verifierStart`, `deriveKeys`, `kdf`, `mac`,
//! `proverFinish`, `verifierConfirm`, `verifierFinish`. Kept in the module per
//! `CONVENTIONS.md` §9.
//!
//! Engine as `hpke`'s probe (2026-10-08 form): the measured region is addressed
//! directly `PAD` below the probe and the call runs under a `PAD`-deep `shim`,
//! so even the caller-side frames of the call (a by-value scalar copy, a
//! returned secret's temporary) are seen. ReleaseFast/ReleaseSmall only — Debug
//! and ReleaseSafe fill `undefined` with 0xaa.
//!
//! Needles are every 16-byte window of every image a secret is held in: the
//! PBKDF output, `w0`, `w1`, `x`, `y` (big-endian, reversed, and as a `p256`
//! scalar), the points `x*P`, `y*P`, `w0*M`, `w0*N` (the password-dictionary
//! oracle if they leak), `Z` and `V` (coordinates as bytes and as field
//! elements), the transcript `TT` (it ends in `w0`), `K_main`,
//! `K_confirmP`, `K_confirmV`, `K_shared` and the HMAC pads derived from a
//! confirmation key.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a key in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const sp = @import("root.zig");
const P256 = @import("p256").P256;
const Scalar = P256.scalar.Scalar;

const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

fn caseKey(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&[_]u8{ 's', 'p', 'a', 'k', 'e', '-', 'p', 'r', 'o', 'b', 'e', i }, &out, .{});
    return out;
}
const n_cases = 2;

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

    /// A big-endian scalar: its bytes, reversed, and the `p256` scalar's
    /// in-memory (Montgomery limb) form.
    fn addScalar(self: *Needles, name: []const u8, s: *const [32]u8) void {
        self.addBytes(name, s);
        const sc = Scalar.fromBytes(s.*, .big) catch return;
        self.addImage(name, std.mem.asBytes(&sc));
    }

    /// A point's affine coordinates, as bytes and as field elements.
    fn addPoint(self: *Needles, name: []const u8, p: P256) void {
        const a = p.affineCoordinates();
        self.addBytes(name, &a.x.toBytes(.big));
        self.addBytes(name, &a.y.toBytes(.big));
        self.addImage(name, std.mem.asBytes(&a.x));
        self.addImage(name, std.mem.asBytes(&a.y));
    }

    /// A confirmation key and the HMAC pads (`key ^ 0x36`, `key ^ 0x5c`) the
    /// MAC derives from it.
    fn addMacKey(self: *Needles, name: []const u8, k: *const [32]u8) void {
        self.addBytes(name, k);
        var ip: [32]u8 = undefined;
        var op: [32]u8 = undefined;
        for (k, &ip, &op) |b, *i, *o| {
            i.* = b ^ 0x36;
            o.* = b ^ 0x5c;
        }
        self.addImage(name, &ip);
        self.addImage(name, &op);
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
// Addressed `PAD` below the probe; the measured call runs under a `PAD`-deep
// frame (`shim`). `paint` and `snapshot` run at the probe's own depth with
// frames far smaller than `PAD`, so no instrument frame overlaps the region.
const PAD = 2048;

var region_lo: usize = 0;
var region_hi: usize = 0;
var snap: [WINDOW]u8 = undefined;

/// An address inside a frame called from the probe.
noinline fn stackHere() usize {
    var x: u8 = 0;
    std.mem.doNotOptimizeAway(&x);
    return @intFromPtr(&x);
}

noinline fn paint() void {
    const p: [*]volatile u8 = @ptrFromInt(region_lo);
    for (0..WINDOW) |i| p[i] = 0xC7;
}

/// Run `call` `PAD` bytes deeper than the probe. `pad` is touched after the
/// call too, so it cannot be a tail call.
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

/// Zero the callee-saved registers before a measured call: they still hold the
/// TEST's values — needles it just computed — and the call's prologue spills
/// them into its frame, where the scan credits them to the call.
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
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE spake2plus: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<10} {d} (5 calls)\n", .{ name, total[i] });
        }
        if (sum != 0) std.debug.print("    hits {d}..{d} B below the region top\n", .{ shallowest, deepest });
    }
    try std.testing.expectEqual(@as(usize, 0), neg_sum);
    try std.testing.expect(pos_sum >= 1); // the scan can see a parked secret
    return sum;
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

// ── the probed calls: exactly as a consumer writes them ─────────────────────

const ctx = "spake2plus probe context";
const id_p = "probe prover";
const id_v = "probe verifier";

var pbkdf: [80]u8 = undefined;
var w0: [32]u8 = undefined;
var w1: [32]u8 = undefined;
var x_sc: [32]u8 = undefined;
var y_sc: [32]u8 = undefined;
var share_p: [65]u8 = undefined;
var share_v: [65]u8 = undefined;
var l_rec: [65]u8 = undefined;
var confirm_p: [32]u8 = undefined;
var confirm_v: [32]u8 = undefined;
var tt_copy: [1024]u8 = undefined;
var tt_len: usize = 0;
var keys: sp.DerivedKeys = undefined;

var fba_buf: [4096]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = undefined;

var w0w1_sink: sp.W0W1 = undefined;
var l_sink: [65]u8 = undefined;
var share_sink: [65]u8 = undefined;
var keys_sink: sp.DerivedKeys = undefined;
var kdf_sink: [64]u8 = undefined;
var mac_sink: [32]u8 = undefined;
var pf_sink: sp.ProverFinishResult = undefined;
var vf_sink: sp.VerifierFinishResult = undefined;
var vc_sink: sp.VerifierConfirmResult = undefined;

noinline fn callW0W1() void {
    sp.computeW0W1(&w0w1_sink, &pbkdf) catch unreachable;
}
noinline fn callL() void {
    l_sink = sp.computeL(&w1) catch unreachable;
}
noinline fn callPStart() void {
    share_sink = sp.proverStart(&x_sc, &w0) catch unreachable;
}
noinline fn callVStart() void {
    share_sink = sp.verifierStart(&y_sc, &w0) catch unreachable;
}
noinline fn callDerive() void {
    sp.deriveKeys(&keys_sink, tt_copy[0..tt_len]);
}
noinline fn callKdf() void {
    sp.kdf(64, &kdf_sink, "", &keys.k_main, "ConfirmationKeys");
}
noinline fn callMac() void {
    mac_sink = sp.mac(&keys.k_confirm_v, &share_p);
}
noinline fn callPFinish() void {
    fba = .init(&fba_buf);
    sp.proverFinish(&pf_sink, fba.allocator(), ctx, id_p, id_v, &w0, &w1, &x_sc, share_p, share_v, confirm_v) catch unreachable;
}
noinline fn callVConfirm() void {
    fba = .init(&fba_buf);
    vc_sink = sp.verifierConfirm(fba.allocator(), ctx, id_p, id_v, &w0, l_rec, &y_sc, share_p, share_v) catch unreachable;
}
noinline fn callVFinish() void {
    fba = .init(&fba_buf);
    sp.verifierFinish(&vf_sink, fba.allocator(), ctx, id_p, id_v, &w0, l_rec, &y_sc, share_p, share_v, confirm_p) catch unreachable;
}

// ── fixtures ────────────────────────────────────────────────────────────────

var z_point: P256 = undefined;
var v_point: P256 = undefined;
var w0m_point: P256 = undefined;
var w0n_point: P256 = undefined;
var xp_point: P256 = undefined;
var yp_point: P256 = undefined;

fn setUp(ci: u8) !void {
    const a = caseKey(ci);
    const b = caseKey(ci + 10);
    const c = caseKey(ci + 20);
    pbkdf[0..32].* = a;
    pbkdf[32..64].* = b;
    pbkdf[64..80].* = c[0..16].*;
    var r: sp.W0W1 = undefined;
    try sp.computeW0W1(&r, &pbkdf);
    w0 = r.w0;
    w1 = r.w1;
    var e: sp.W0W1 = undefined;
    try sp.computeW0W1(&e, &caseKey80(ci + 40));
    x_sc = e.w0;
    y_sc = e.w1;
    l_rec = try sp.computeL(&w1);
    share_p = try sp.proverStart(&x_sc, &w0);
    share_v = try sp.verifierStart(&y_sc, &w0);

    fba = .init(&fba_buf);
    const vc = try sp.verifierConfirm(fba.allocator(), ctx, id_p, id_v, &w0, l_rec, &y_sc, share_p, share_v);
    confirm_v = vc.confirm_v;
    try finishFor();

    xp_point = try P256.basePoint.mul(x_sc, .big);
    yp_point = try P256.basePoint.mul(y_sc, .big);
    w0m_point = try sp.mPoint().mul(w0, .big);
    w0n_point = try sp.nPoint().mul(w0, .big);
    z_point = try (try P256.fromSec1(&share_v)).sub(w0n_point).mul(x_sc, .big);
    v_point = try (try P256.fromSec1(&share_v)).sub(w0n_point).mul(w1, .big);
    leak_src = w0;
}

fn caseKey80(i: u8) [80]u8 {
    var out: [80]u8 = undefined;
    out[0..32].* = caseKey(i);
    out[32..64].* = caseKey(i + 1);
    out[64..80].* = caseKey(i + 2)[0..16].*;
    return out;
}

/// Run the whole handshake once through the public API to fill `confirm_p`,
/// `tt_copy` and `keys`.
fn finishFor() !void {
    fba = .init(&fba_buf);
    var pf: sp.ProverFinishResult = undefined;
    try sp.proverFinish(&pf, fba.allocator(), ctx, id_p, id_v, &w0, &w1, &x_sc, share_p, share_v, confirm_v);
    confirm_p = pf.confirm_p;
    @memcpy(tt_copy[0..pf.tt.len], pf.tt);
    tt_len = pf.tt.len;
    sp.deriveKeys(&keys, pf.tt);
}

fn addCommon(n: *Needles) void {
    n.addScalar("w0", &w0);
    n.addBytes("control", &leak_src);
}

fn addSchedule(n: *Needles) void {
    // Only the secret tail of TT: `Z || V || w0` with their length prefixes
    // (the rest is context, identities, M, N and the shares — all public).
    n.addImage("tt", tt_copy[tt_len - (73 + 73 + 40) .. tt_len]);
    n.addBytes("k_main", &keys.k_main);
    n.addMacKey("k_confirm_p", &keys.k_confirm_p);
    n.addMacKey("k_confirm_v", &keys.k_confirm_v);
    n.addBytes("k_shared", &keys.k_shared);
}

fn addZV(n: *Needles) void {
    n.addPoint("Z", z_point);
    n.addPoint("V", v_point);
    n.addPoint("w0M", w0m_point);
    n.addPoint("w0N", w0n_point);
}

test "STACKPROBE: no password/scalar residue after computeW0W1, computeL, proverStart, verifierStart" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        var n: Needles = .{};

        n.addBytes("pbkdf", &pbkdf);
        n.addScalar("w0", &w0);
        n.addScalar("w1", &w1);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("computeW0W1", callW0W1, &n);

        n = .{};
        n.addScalar("w1", &w1);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("computeL", callL, &n);

        n = .{};
        addCommon(&n);
        n.addScalar("x", &x_sc);
        n.addPoint("xP", xp_point);
        n.addPoint("w0M", w0m_point);
        n.sort();
        bad += try runProbe("proverStart", callPStart, &n);

        n = .{};
        addCommon(&n);
        n.addScalar("y", &y_sc);
        n.addPoint("yP", yp_point);
        n.addPoint("w0N", w0n_point);
        n.sort();
        bad += try runProbe("verifierStart", callVStart, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no key-schedule residue after deriveKeys, kdf, mac" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        var n: Needles = .{};

        addSchedule(&n);
        n.addScalar("w0", &w0);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("deriveKeys", callDerive, &n);

        n = .{};
        n.addBytes("k_main", &keys.k_main);
        n.addMacKey("k_confirm_p", &keys.k_confirm_p);
        n.addMacKey("k_confirm_v", &keys.k_confirm_v);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("kdf (64)", callKdf, &n);

        n = .{};
        n.addMacKey("k_confirm_v", &keys.k_confirm_v);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("mac", callMac, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no Z/V/key residue after proverFinish, verifierConfirm, verifierFinish" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        var n: Needles = .{};

        addCommon(&n);
        n.addScalar("w1", &w1);
        n.addScalar("x", &x_sc);
        addZV(&n);
        addSchedule(&n);
        n.sort();
        bad += try runProbe("proverFinish", callPFinish, &n);

        n = .{};
        addCommon(&n);
        n.addScalar("y", &y_sc);
        addZV(&n);
        addSchedule(&n);
        n.sort();
        bad += try runProbe("verifierConfirm", callVConfirm, &n);

        n = .{};
        addCommon(&n);
        n.addScalar("y", &y_sc);
        addZV(&n);
        addSchedule(&n);
        n.sort();
        bad += try runProbe("verifierFinish", callVFinish, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
