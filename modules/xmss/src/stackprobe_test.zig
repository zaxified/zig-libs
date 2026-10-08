// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for key generation and signing: `keyGen`, and
//! `sign` at leaf 0 (the sequential path) and at leaf 5 (`sign` first rebuilds
//! the traversal state for an index it did not track). Kept in the module per
//! `CONVENTIONS.md` §9. Reduced height h = 4, the height the unit tests use
//! (h = 10 keygen is ~40 s in Debug).
//!
//! Method as `ssh`'s probe: paint a stack window below the probe, run the call
//! `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles (each 32-byte value as its two 16-byte halves; windows with fewer
//! than 8 distinct bytes are skipped):
//! - `SK_SEED` and `SK_PRF`;
//! - the WOTS+ chain values at positions 0..w-2 of every leaf (position 0 is
//!   the private key element, `PRF_keygen(SK_SEED, SEED || ADRS)`). For the
//!   leaf a measured `sign` used, the positions at or above the published
//!   digit follow from the signature and are dropped; the positions below it
//!   forge lower digits. Any other leaf's values forge that leaf's index.
//! Not needles: the randomizer `r = PRF(SK_PRF, idx)` (the signature publishes
//! it, and it is only unpredictable, not secret, once `sign` returns), the
//! message hash, the tree nodes and the root (public).
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const xmss = @import("root.zig");

const n = xmss.n;
const w = xmss.w;
const X = xmss.XmssSha2(4, 0xDDDDDDDD); // 16 one-time keys
const Sha256 = std.crypto.hash.sha2.Sha256;

const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

const msg = "xmss dead-stack probe message";

fn seedOf(offset: u8) [n]u8 {
    var s: [n]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = @truncate(i + offset);
    return s;
}
const sk_seed = seedOf(3);
const sk_prf = seedOf(103);
const pub_seed = seedOf(203);

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 40000;

const Needles = struct {
    win: [max_windows]u128 = undefined,
    owner: [max_windows]u8 = undefined,
    len: usize = 0,

    const names = [_][]const u8{ "seed", "sk_prf", "used_leaf", "other_leaf" };

    fn addValue(self: *Needles, id: u8, v: *const [n]u8) void {
        for ([_]usize{ 0, W }) |off| {
            if (distinct(v[off..][0..W]) < 8) continue;
            self.win[self.len] = std.mem.readInt(u128, v[off..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    fn distinct(win: *const [W]u8) usize {
        var seen: [256]bool = @splat(false);
        var c: usize = 0;
        for (win) |b| {
            if (!seen[b]) c += 1;
            seen[b] = true;
        }
        return c;
    }

    fn sort(self: *Needles) void {
        const Ctx = struct {
            s: *Needles,
            pub fn lessThan(c: @This(), a: usize, b: usize) bool {
                return c.s.win[a] < c.s.win[b];
            }
            pub fn swap(c: @This(), a: usize, b: usize) void {
                std.mem.swap(u128, &c.s.win[a], &c.s.win[b]);
                std.mem.swap(u8, &c.s.owner[a], &c.s.owner[b]);
            }
        };
        std.sort.pdqContext(0, self.len, Ctx{ .s = self });
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

const Hits = [Needles.names.len]usize;

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
inline fn measure(call: *const fn () void, needles: *const Needles) Hits {
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    return scan(needles);
}

fn runProbe(label: []const u8, setup: ?*const fn () void, call: *const fn () void, needles: *const Needles) !usize {
    region_hi = stackHere() - PAD;
    region_lo = region_hi - WINDOW;

    const neg = measure(callInnocent, needles);
    const pos = measure(callLeaky, needles);

    var total: Hits = @splat(0);
    var shallowest: usize = 0;
    var deepest: usize = 0;
    for (0..5) |_| {
        if (setup) |s| s();
        for (&total, measure(call, needles)) |*t, x| t.* += x;
        if (hit_min_depth != 0 and (shallowest == 0 or hit_min_depth < shallowest)) shallowest = hit_min_depth;
        if (hit_max_depth > deepest) deepest = hit_max_depth;
    }
    if (setup) |s| s();
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
        std.debug.print("\n=== STACKPROBE xmss: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
        for (Needles.names, 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<14} {d} (5 calls)\n", .{ name, total[i] });
        }
        if (sum != 0) std.debug.print("    hits {d}..{d} B below the region top\n", .{ shallowest, deepest });
    }
    try std.testing.expectEqual(@as(usize, 0), neg_sum);
    try std.testing.expect(pos_sum >= 1); // the scan can see a parked secret
    return sum;
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

var kp: X.KeyPair = undefined;
var pristine: X.KeyPair = undefined;
var start_idx: u32 = 0;
var sig: [X.signature_length]u8 = undefined;
var ref_sig: [X.signature_length]u8 = undefined;

noinline fn callKeyGen() void {
    X.keyGen(&kp, &sk_seed, &sk_prf, &pub_seed);
    std.mem.doNotOptimizeAway(&kp);
}

fn setupSign() void {
    kp = pristine;
    kp.sk.idx = start_idx;
}

noinline fn callSign() void {
    X.sign(&kp.sk, &sig, msg) catch unreachable;
    std.mem.doNotOptimizeAway(&sig);
}

var auth_out: [X.h][n]u8 = undefined;

noinline fn callBuildAuth() void {
    X.buildAuth(&sk_seed, &pub_seed, 5, &auth_out);
    std.mem.doNotOptimizeAway(&auth_out);
}

/// Every chain value of every leaf, plus the two secret seeds. For `used`,
/// the positions `ref_sig` publishes (the digit and above) are left out.
fn buildNeedles(needles: *Needles, used: ?u32) void {
    needles.len = 0;
    for (0..X.max_signatures) |leaf| {
        var adrs = xmss.Adrs{};
        adrs.setType(xmss.Adrs.type_ots);
        adrs.setOtsAddress(@intCast(leaf));
        var starts: [xmss.wots_len][n]u8 = undefined;
        xmss.wotsSkGen(&starts, &sk_seed, &pub_seed, &adrs);
        const is_used = used != null and used.? == leaf;
        for (starts, 0..) |start, i| {
            var a = adrs;
            a.setChainAddress(@intCast(i));
            const published = ref_sig[4 + n + i * n ..][0..n];
            var value = start;
            var pos: u32 = 0;
            while (pos < w - 1) : (pos += 1) {
                if (is_used and std.mem.eql(u8, &value, published)) break;
                needles.addValue(if (is_used) 2 else 3, &value);
                xmss.chain(&value, pos, 1, &pub_seed, &a);
            }
        }
    }
    needles.addValue(0, &sk_seed);
    needles.addValue(1, &sk_prf);
    needles.sort();
}

var needle_set: Needles = .{};

test "STACKPROBE: no seed or WOTS+ chain value on the dead stack after keyGen and sign" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    leak_src = sk_seed;
    X.keyGen(&pristine, &sk_seed, &sk_prf, &pub_seed);
    var bad: usize = 0;

    buildNeedles(&needle_set, null);
    bad += try runProbe("keyGen", null, callKeyGen, &needle_set);

    // Leaf 0 is the plain sequential path; at leaf 5 `sign` first rebuilds
    // the traversal state for an index it did not track.
    for ([_]u32{ 0, 5 }) |idx| {
        start_idx = idx;
        setupSign();
        try X.sign(&kp.sk, &ref_sig, msg);
        buildNeedles(&needle_set, idx);
        setupSign();
        callSign();
        try std.testing.expectEqualSlices(u8, &ref_sig, &sig);
        bad += try runProbe(if (idx == 0) "sign at leaf 0" else "sign at leaf 5 (rebuild)", setupSign, callSign, &needle_set);
    }

    // `buildAuth` (the from-scratch reference) derives every leaf but signs
    // nothing: no leaf has a published digit.
    buildNeedles(&needle_set, null);
    bad += try runProbe("buildAuth", null, callBuildAuth, &needle_set);
    try std.testing.expectEqual(@as(usize, 0), bad);
}
