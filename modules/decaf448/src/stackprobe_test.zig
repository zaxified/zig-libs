// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the secret-scalar paths: `Element.scalarMul`,
//! `scalar.invert` and `scalar.random`. Kept in the module per
//! `CONVENTIONS.md` §9. Engine and method as `ed448`'s `stackprobe_test.zig`:
//! paint, call, scan every 16-byte window of every secret image, next to a
//! NEGATIVE and a POSITIVE control. ReleaseFast/ReleaseSmall only.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Element = root.Element;
const scalar = root.scalar;
const Shake256 = std.crypto.hash.sha3.Shake256;

const WINDOW = 256 * 1024;
const LEAK = 57;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

/// Audit-local keys (not from any vector): SHAKE of a label, so no 16-byte
/// window of them is a run of zeros or of paint that a dead stack holds anyway.
fn caseBytes(comptime n: usize, label: u8, i: u8) [n]u8 {
    var out: [n]u8 = undefined;
    Shake256.hash(&[_]u8{ 'd', 'e', 'c', 'a', 'f', label, i }, &out, .{});
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
        std.debug.print("\n=== STACKPROBE decaf448: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

var cur_s: scalar.CompressedScalar = undefined;
var cur_e: Element = undefined;
var rand_io: std.Io = undefined;
var last_random: scalar.CompressedScalar = undefined;

noinline fn callScalarMul() void {
    const r = cur_e.scalarMul(&cur_s);
    std.mem.doNotOptimizeAway(&r);
}

noinline fn callInvert() void {
    var r = scalar.invert(cur_s);
    std.mem.doNotOptimizeAway(&r);
    std.crypto.secureZero(u8, &r);
}

noinline fn callRandom() void {
    scalar.random(&last_random, rand_io) catch unreachable;
}

test "STACKPROBE: no scalar residue on the dead stack after scalarMul and invert" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        cur_s = scalar.fromWide(caseBytes(114, 's', @intCast(ci)));
        cur_e = root.hashToElement("probe point", "decaf448-probe") catch unreachable;
        leak_src = @splat(0x5a);
        leak_src[0..cur_s.len].* = cur_s;

        var n: Needles = .{};
        n.addImage("s", &cur_s);
        n.addImage("s (ed448 form)", &scalar.toEd448(cur_s));
        n.sort();
        bad += try runProbe("Element.scalarMul", callScalarMul, &n);

        n = .{};
        n.addImage("s", &cur_s);
        n.addImage("s^-1", &scalar.invert(cur_s));
        n.sort();
        bad += try runProbe("scalar.invert", callInvert, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: scalar.random leaves neither its draw nor its result on the dead stack" {
    try skipUnlessOptimized();
    var th = std.Io.Threaded.init(std.testing.allocator, .{});
    defer th.deinit();
    rand_io = th.io();
    // The draw is unknown until the call returns: the needle is the result
    // the measured call itself copied out to static memory.
    var bad: usize = 0;
    region_hi = stackHere() - PAD;
    region_lo = region_hi - WINDOW;
    for (0..n_cases) |_| {
        paint();
        shim(callRandom);
        snapshot();
        var n: Needles = .{};
        n.addImage("r", &last_random);
        n.sort();
        const hits = scan(&n);
        var sum: usize = 0;
        for (hits) |h| sum += h;
        if (sum != 0) std.debug.print("\n=== STACKPROBE decaf448: scalar.random: RESIDUE r {d} ===\n", .{sum});
        bad += sum;
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
