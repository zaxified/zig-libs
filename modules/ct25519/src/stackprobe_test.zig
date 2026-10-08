// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the secret-scalar paths: `mul`, `mulBase`,
//! `mulRistretto`, `mulRistrettoBase`, `mulMultiRistretto` and X25519
//! (`scalarmult`, `recoverPublicKey`). Kept in the module per
//! `CONVENTIONS.md` §9. Engine and method as `ed448`'s `stackprobe_test.zig`:
//! paint, call, scan every 16-byte window of every secret image (the scalar
//! little- and big-endian, the X25519 shared secret), next to a NEGATIVE and a
//! POSITIVE control. ReleaseFast/ReleaseSmall only.

const std = @import("std");
const builtin = @import("builtin");
const ct = @import("root.zig");
const Shake256 = std.crypto.hash.sha3.Shake256;

const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

/// Audit-local keys (not from any vector): SHAKE of a label, so no 16-byte
/// window of them is a run of zeros or of paint that a dead stack holds anyway.
fn caseBytes(comptime n: usize, label: u8, i: u8) [n]u8 {
    var out: [n]u8 = undefined;
    Shake256.hash(&[_]u8{ 'c', 't', '2', '5', '5', label, i }, &out, .{});
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
        std.debug.print("\n=== STACKPROBE ct25519: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

var cur_s: [32]u8 = undefined;
var cur_s2: [32]u8 = undefined;
var cur_p: ct.Edwards25519 = undefined;
var cur_r: ct.Ristretto255 = undefined;
var cur_peer: [32]u8 = undefined;
var x_shared: [32]u8 = undefined;
var msm_scalars: [2][32]u8 = undefined;
var msm_points: [2]ct.Ristretto255 = undefined;

noinline fn callMul() void {
    const q = ct.mul(cur_p, cur_s);
    std.mem.doNotOptimizeAway(&q);
}
noinline fn callMulBase() void {
    const q = ct.mulBase(cur_s);
    std.mem.doNotOptimizeAway(&q);
}
noinline fn callMulRistretto() void {
    const q = ct.mulRistretto(cur_r, cur_s);
    std.mem.doNotOptimizeAway(&q);
}
noinline fn callMulRistrettoBase() void {
    const q = ct.mulRistrettoBase(cur_s);
    std.mem.doNotOptimizeAway(&q);
}
noinline fn callMulMulti() void {
    // The scalars array is the caller's own data: kept in static memory.
    msm_scalars = .{ cur_s, cur_s2 };
    msm_points = .{ cur_r, ct.Ristretto255.basePoint };
    const q = ct.mulMultiRistretto(&msm_scalars, &msm_points);
    std.mem.doNotOptimizeAway(&q);
}
noinline fn callX25519() void {
    ct.X25519.scalarmultInto(&x_shared, &cur_s, cur_peer) catch unreachable;
}
noinline fn callX25519Public() void {
    const pk = ct.X25519.recoverPublicKey(cur_s) catch unreachable;
    std.mem.doNotOptimizeAway(&pk);
}

fn addScalar(n: *Needles, name: []const u8, s: [32]u8) void {
    n.addImage(name, &s);
    var r = s;
    std.mem.reverse(u8, &r);
    n.addImage(name, &r);
}

test "STACKPROBE: no scalar or shared-secret residue on the dead stack after the secret-scalar multiplies" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        cur_s = ct.Edwards25519.scalar.reduce(caseBytes(32, 's', @intCast(ci)));
        cur_s2 = ct.Edwards25519.scalar.reduce(caseBytes(32, 't', @intCast(ci)));
        cur_p = ct.mulBase(caseBytes(32, 'p', @intCast(ci)));
        cur_r = ct.mulRistrettoBase(ct.Edwards25519.scalar.reduce(caseBytes(32, 'q', @intCast(ci))));
        cur_peer = try ct.X25519.recoverPublicKey((caseBytes(32, 'x', @intCast(ci))));
        leak_src = cur_s;

        var n: Needles = .{};
        addScalar(&n, "s", cur_s);
        addScalar(&n, "s2", cur_s2);
        n.sort();
        const calls = [_]struct { name: []const u8, f: *const fn () void }{
            .{ .name = "mul", .f = callMul },
            .{ .name = "mulBase", .f = callMulBase },
            .{ .name = "mulRistretto", .f = callMulRistretto },
            .{ .name = "mulRistrettoBase", .f = callMulRistrettoBase },
            .{ .name = "mulMultiRistretto", .f = callMulMulti },
            .{ .name = "X25519.recoverPublicKey", .f = callX25519Public },
        };
        for (calls) |c| bad += try runProbe(c.name, c.f, &n);

        var clamped = cur_s;
        std.crypto.ecc.Edwards25519.scalar.clamp(&clamped);
        n = .{};
        addScalar(&n, "s", cur_s);
        addScalar(&n, "s (clamped)", clamped);
        var shared: [32]u8 = undefined;
        try ct.X25519.scalarmultInto(&shared, &cur_s, cur_peer);
        n.addImage("shared", &shared);
        n.sort();
        bad += try runProbe("X25519.scalarmultInto", callX25519, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
