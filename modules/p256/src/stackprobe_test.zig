// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the secret-scalar paths: ECDSA signing (the
//! module's own `ecdsaSign`/`ecdsaSignDeterministic` and the std-surface
//! `EcdsaP256Sha256` that jwt ES256 and jwe sign through), key-pair derivation
//! and ECDH (`P256.mul` with a secret scalar). Kept in the module per
//! `CONVENTIONS.md` §9.
//!
//! Method as `bip340`'s and `threshold_ecdsa`'s probes: paint a stack window,
//! call at that depth, claim an equally large UNINITIALISED buffer there and
//! look for secrets. ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe fill
//! `undefined` with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in
//! (big-endian, little-endian, the scalar field's in-memory form), so a half
//! copy or a limb pair counts too. The nonce is never re-derived: it is solved
//! from the signature the call returned, `k = s⁻¹·(e + r·d)`, so the probe
//! sees whatever nonce the signer actually used — std's included.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks `d` in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const p256 = @import("root.zig");

const Scalar = p256.Scalar;
const P256 = p256.P256;
const Ecdsa = p256.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

pub const msg = "p256 dead-stack probe message";

/// Audit-local keys (not from any vector): hashes of a label, so no 16-byte
/// window of them is a run of zeros or of paint that a dead stack holds anyway.
fn caseKey(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'p', '2', '5', '6', '-', 'k', 'e', 'y', i }, &out, .{});
    return out;
}
const n_cases = 2;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 2048;

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

    fn addScalar(self: *Needles, name: []const u8, s: Scalar) void {
        const be = s.toBytes(.big);
        self.addImage(name, &be);
        const le = s.toBytes(.little);
        self.addImage(name, &le);
        self.addImage(name, std.mem.asBytes(&s));
    }

    fn addBytes32(self: *Needles, name: []const u8, b: [32]u8) void {
        self.addImage(name, &b);
        var r = b;
        std.mem.reverse(u8, &r);
        self.addImage(name, &r);
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
// own header and locals hid the top few hundred bytes (2026-10-08: a stale
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
/// (2026-10-08: a negative-control "hit" of `x mod q` between two saved stack
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
/// `runProbe` computed (2026-10-08).
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
        std.debug.print("\n=== STACKPROBE p256: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

fn e() Scalar {
    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = h;
    return Scalar.fromBytes48(wide, .big);
}

/// Needles for a signature `sig` made with key `sk`: `d`, the nonce solved
/// from the signature, its inverse, `r·d` and `e + r·d`.
fn signNeedles(n: *Needles, sk: [32]u8, sig: [64]u8) !void {
    const d = try Scalar.fromBytes(sk, .big);
    const r = try Scalar.fromBytes(sig[0..32].*, .big);
    const s = try Scalar.fromBytes(sig[32..64].*, .big);
    const rd = r.mul(d);
    const erd = e().add(rd);
    const k = s.invert().mul(erd);
    n.addScalar("d", d);
    n.addScalar("k", k);
    n.addScalar("k^-1", k.invert());
    n.addScalar("r*d", rd);
    n.addScalar("e+r*d", erd);
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

var cur_sk: [32]u8 = undefined;
var cur_nonce: [32]u8 = undefined;
var cur_pair: Ecdsa.KeyPair = undefined;
var cur_peer: P256 = undefined;
var cur_std_sk: Ecdsa.SecretKey = undefined;
// Results land in static memory: the caller's own storage is not the probe's concern.
var pair_sink: Ecdsa.KeyPair = undefined;
var shared_sink: P256 = undefined;
var shared_x_sink: [32]u8 = undefined;

noinline fn callEcdsaSign() void {
    const sig = p256.sign.ecdsaSign(&cur_sk, msg, &cur_nonce) catch unreachable;
    std.mem.doNotOptimizeAway(&sig);
}

noinline fn callEcdsaSignDeterministic() void {
    const sig = p256.sign.ecdsaSignDeterministic(&cur_sk, msg) catch unreachable;
    std.mem.doNotOptimizeAway(&sig);
}

noinline fn callStdSign() void {
    const sig = cur_pair.sign(msg, null) catch unreachable;
    std.mem.doNotOptimizeAway(&sig);
}

noinline fn callStdSignNoise() void {
    const sig = cur_pair.sign(msg, cur_nonce) catch unreachable;
    std.mem.doNotOptimizeAway(&sig);
}

noinline fn callFromSecretKey() void {
    Ecdsa.KeyPair.fromSecretKeyInto(&pair_sink, &cur_std_sk) catch unreachable;
}

noinline fn callEcdh() void {
    cur_peer.mulInto(&shared_sink, &cur_sk, .big) catch unreachable;
    shared_x_sink = shared_sink.affineCoordinates().x.toBytes(.big);
}

test "STACKPROBE: no key or nonce residue on the dead stack after ECDSA signing" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        cur_sk = caseKey(@intCast(ci));
        Sha256.hash(&cur_sk, &cur_nonce, .{});
        cur_pair = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(cur_sk));
        leak_src = cur_sk;

        const signers = [_]struct { name: []const u8, call: *const fn () void, sig: [64]u8 }{
            .{ .name = "ecdsaSign", .call = callEcdsaSign, .sig = try p256.sign.ecdsaSign(&cur_sk, msg, &cur_nonce) },
            .{ .name = "ecdsaSignDeterministic", .call = callEcdsaSignDeterministic, .sig = try p256.sign.ecdsaSignDeterministic(&cur_sk, msg) },
            .{ .name = "EcdsaP256Sha256 sign", .call = callStdSign, .sig = (try cur_pair.sign(msg, null)).toBytes() },
            .{ .name = "EcdsaP256Sha256 sign+noise", .call = callStdSignNoise, .sig = (try cur_pair.sign(msg, cur_nonce)).toBytes() },
        };
        for (signers) |sg| {
            var n: Needles = .{};
            try signNeedles(&n, cur_sk, sg.sig);
            n.sort();
            bad += try runProbe(sg.name, sg.call, &n);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no key residue on the dead stack after KeyPair.fromSecretKey and ECDH" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        cur_sk = caseKey(@intCast(ci));
        cur_std_sk = try Ecdsa.SecretKey.fromBytes(cur_sk);
        leak_src = cur_sk;
        cur_peer = try P256.basePoint.mul(caseKey(0xee), .big);

        var n: Needles = .{};
        n.addScalar("d", try Scalar.fromBytes(cur_sk, .big));
        n.sort();
        bad += try runProbe("KeyPair.fromSecretKeyInto", callFromSecretKey, &n);

        const shared = (try cur_peer.mul(cur_sk, .big)).affineCoordinates();
        n = .{};
        n.addScalar("d", try Scalar.fromBytes(cur_sk, .big));
        n.addBytes32("shared x", shared.x.toBytes(.big));
        n.addBytes32("shared y", shared.y.toBytes(.big));
        n.addImage("shared x fe", std.mem.asBytes(&shared.x));
        n.sort();
        bad += try runProbe("ECDH P256.mulInto", callEcdh, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
