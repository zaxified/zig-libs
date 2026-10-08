// SPDX-License-Identifier: MIT

//! Dead-stack and freed-heap residue probe for LMS / HSS key generation and
//! signing: `Tree.init` / `deinit`, `LmsSecretKey.sign`, and the HSS
//! `SecretKey.init` + first `sign` (which builds the child tree) and a later
//! `sign` on the built key. Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `ssh`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles (16-byte windows of every image a secret is held in):
//! - SEED (and, for HSS, the child tree's SEED derived from it);
//! - `x_q[i] = H(I ‖ q ‖ i ‖ 0xff ‖ SEED)` for every `i` of each probed leaf;
//! - the OTS chain values between `x` and the public end (`y_i` of a
//!   signature is in the signature, and the values above it follow from it,
//!   so a signing call only needles the steps BELOW `a_i`; key generation
//!   needles every step below the chain end, for every leaf).
//! `I` is public and not needled. After a call that frees its key the
//! allocator's backing store is scanned for the same needles.
//! Windows with fewer than 8 distinct bytes are skipped.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const lms = @import("root.zig");
const core = @import("core.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Tree = lms.Tree;
const LmsSecretKey = lms.LmsSecretKey;
const SecretKey = lms.SecretKey;
const Level = lms.Level;

const WINDOW = 512 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

const lms_set: lms.ParamSet = .sha256_m32_h5;
const ots_set: lms.OtsParamSet = .sha256_n32_w4;
const levels = [_]Level{
    .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w4 },
    .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w4 },
};

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 1 << 18;

const Needles = struct {
    win: [max_windows]u128 = undefined,
    owner: [max_windows]u8 = undefined,
    len: usize = 0,
    names: [8][]const u8 = undefined,
    n_names: usize = 0,

    fn reset(self: *Needles) void {
        self.len = 0;
        self.n_names = 0;
    }

    fn addImage(self: *Needles, name: []const u8, image: []const u8) void {
        const id: u8 = @intCast(self.lookupName(name));
        var i: usize = 0;
        while (i + W <= image.len) : (i += 1) {
            if (distinct(image[i..][0..W]) < 8) continue;
            self.put(id, image[i..][0..W]);
        }
    }

    /// Only the first window of `image`: a chain value has 17 overlapping
    /// windows and one is enough to see it (the OTS chains are many).
    fn addFirst(self: *Needles, name: []const u8, image: []const u8) void {
        const id: u8 = @intCast(self.lookupName(name));
        if (distinct(image[0..W]) < 8) return;
        self.put(id, image[0..W]);
    }

    fn put(self: *Needles, id: u8, w: *const [W]u8) void {
        self.win[self.len] = std.mem.readInt(u128, w, .little);
        self.owner[self.len] = id;
        self.len += 1;
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

var needles: Needles = .{};

const Hits = [8]usize;

/// SEED, then (for the key generation of every leaf, `msg == null`, or the
/// signature of leaf `q` under `msg`) `x_q[i]` and the chain values below the
/// public end. The helpers are the module's own primitives.
fn otsNeedles(n: *Needles, ots: lms.OtsParamSet, id: *const [16]u8, q: u32, seed: *const [32]u8, msg: ?[]const u8) void {
    const w = ots.w();
    const top: u16 = (@as(u16, 1) << w) - 1;
    var s: [34]u8 = undefined;
    if (msg) |m| {
        const c = core.deriveRandomizer(id, q, seed);
        s = core.withChecksum(ots, &core.messageHash(id, q, &c, m));
    }
    var i: u16 = 0;
    while (i < ots.p()) : (i += 1) {
        const limit: u16 = if (msg != null) core.coef(&s, i, w) else top;
        var tmp: [32]u8 = undefined;
        core.deriveX(&tmp, id, q, i, seed);
        // a signature with a_i == 0 publishes x itself
        if (limit > 0) n.addImage("x_q[i]", &tmp);
        var j: u16 = 0;
        while (j + 1 < limit) : (j += 1) {
            tmp = core.chainHash(id, q, i, @intCast(j), &tmp);
            n.addFirst("chain", &tmp);
        }
    }
}

/// Key generation touches every leaf; `signed` (a leaf the same call signs)
/// is left to its signing needles, because its signature is public and holds
/// chain values the full set would flag.
fn allLeavesNeedles(n: *Needles, id: *const [16]u8, seed: *const [32]u8, signed: ?u32) void {
    var q: u32 = 0;
    while (q < lms_set.leaves()) : (q += 1) {
        if (signed != null and signed.? == q) continue;
        otsNeedles(n, ots_set, id, q, seed, null);
    }
}

/// The HSS child's SEED and I for level 1 under leaf path `{0}` — the module's
/// private `deriveChild` formula.
fn childOf(master: *const [32]u8) struct { seed: [32]u8, id: [16]u8 } {
    var out: [2][32]u8 = undefined;
    for (&out, 0..) |*o, tag| {
        var h = Sha256.init(.{});
        h.update("zig-libs lms hss child v1");
        h.update(&[_]u8{ @intCast(tag), 1 });
        h.update(&std.mem.toBytes(std.mem.nativeToBig(u32, 0)));
        h.update(master);
        o.* = h.finalResult();
    }
    return .{ .seed = out[0], .id = out[1][0..16].* };
}

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

fn scan(buf: []const u8, n: *const Needles, stack: bool) Hits {
    var hits: Hits = @splat(0);
    hit_min_depth = 0;
    hit_max_depth = 0;
    var skip_until: usize = 0;
    var i: usize = 0;
    while (i + W <= buf.len) : (i += 1) {
        if (i < skip_until) continue;
        if (n.find(std.mem.readInt(u128, buf[i..][0..W], .little))) |id| {
            hits[id] += 1;
            if (stack) {
                const d = buf.len - i;
                if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
                if (d > hit_max_depth) hit_max_depth = d;
            }
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
    return scan(&snap, n, true);
}

/// Returns stack residue; `heap` (when non-null) is scanned after the final
/// call and its residue added to `heap_out`.
fn runProbe(label: []const u8, call: *const fn () void, n: *const Needles, heap: ?[]const u8) !usize {
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

    var heap_hits: Hits = @splat(0);
    if (heap) |h| heap_hits = scan(h, n, false);

    var sum: usize = 0;
    for (total) |h| sum += h;
    var heap_sum: usize = 0;
    for (heap_hits) |h| heap_sum += h;
    var neg_sum: usize = 0;
    for (neg) |h| neg_sum += h;
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or heap_sum != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE lms: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B heap={d} ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth, heap_sum });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<14} {d} (5 calls)\n", .{ name, total[i] });
            if (heap_hits[i] != 0) std.debug.print("    HEAP    {s:<14} {d}\n", .{ name, heap_hits[i] });
        }
        if (sum != 0) std.debug.print("    hits {d}..{d} B below the region top\n", .{ shallowest, deepest });
    }
    try std.testing.expectEqual(@as(usize, 0), neg_sum);
    try std.testing.expect(pos_sum >= 1); // the scan can see a parked secret
    return sum + heap_sum;
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────
// The `inline` adapters are the one place the call shape lives.

var cur_seed: [32]u8 = undefined;
var cur_id: [16]u8 = undefined;

var heap_buf: [128 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;
var key_buf: [128 * 1024]u8 = undefined;
var key_fba: std.heap.FixedBufferAllocator = undefined;

var tree_sink: Tree = undefined;
var lsk: LmsSecretKey = undefined; // prebuilt, signs in `callLmsSign`
var hsk: SecretKey = undefined; // built per call in `callHssBuild`, moved into `signing`
var signing: lms.SigningKey = undefined;
var hsk_built: SecretKey = undefined; // prebuilt, signs in `callHssSign`
var sig_buf: [8192]u8 = undefined;

const message = "stackprobe lms message";

inline fn treeInit(out: *Tree, gpa: std.mem.Allocator, seed: *const [32]u8) !void {
    try Tree.init(out, gpa, lms_set, ots_set, cur_id, seed);
}

inline fn lskInit(out: *LmsSecretKey, gpa: std.mem.Allocator, seed: *const [32]u8) !void {
    try LmsSecretKey.init(out, gpa, lms_set, ots_set, cur_id, seed);
}

inline fn skInit(out: *SecretKey, gpa: std.mem.Allocator, seed: *const [32]u8) !void {
    try SecretKey.init(out, gpa, &levels, seed, cur_id, null);
}

noinline fn callLmsKeygen() void {
    heap_fba.reset();
    treeInit(&tree_sink, heap_fba.allocator(), &cur_seed) catch unreachable;
    tree_sink.deinit();
}

noinline fn callLmsSign() void {
    lsk.q = 3;
    const sig = lsk.sign(message, &sig_buf) catch unreachable;
    std.mem.doNotOptimizeAway(sig.ptr);
}

noinline fn callHssBuild() void {
    heap_fba.reset();
    skInit(&hsk, heap_fba.allocator(), &cur_seed) catch unreachable;
    lms.SigningKey.init(&signing, &hsk, null);
    const sig = signing.sign(message, &sig_buf) catch unreachable;
    std.mem.doNotOptimizeAway(sig.ptr);
    signing.deinit();
}

noinline fn callHssSign() void {
    hsk_built.pos = .{};
    const sig = hsk_built.sign(message, &sig_buf) catch unreachable;
    std.mem.doNotOptimizeAway(sig.ptr);
}

/// A high-entropy seed (a repeated byte would be skipped as low-entropy).
fn caseSeed(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'l', 'm', 's', '-', 's', 'e', 'e', 'd', i }, &out, .{});
    return out;
}

test "STACKPROBE: no seed, OTS private value or chain value on the dead stack or in freed heap after LMS / HSS key generation and signing" {
    try skipUnlessOptimized();
    heap_fba = .init(&heap_buf);
    key_fba = .init(&key_buf);
    cur_seed = caseSeed(1);
    cur_id = caseSeed(2)[0..16].*;
    leak_src = cur_seed;
    const n = &needles;
    var bad: usize = 0;

    // ── LMS: key generation (all 32 leaves), then a signature at leaf 3 ──
    {
        n.reset();
        _ = n.lookupName("SEED");
        n.addImage("SEED", &cur_seed);
        allLeavesNeedles(n, &cur_id, &cur_seed, null);
        n.sort();
        callLmsKeygen(); // warm
        bad += try runProbe("Tree.init + deinit (h5/w4)", callLmsKeygen, n, &heap_buf);
    }
    try lskInit(&lsk, key_fba.allocator(), &cur_seed);
    defer lsk.deinit();
    {
        n.reset();
        n.addImage("SEED", &cur_seed);
        otsNeedles(n, ots_set, &cur_id, 3, &cur_seed, message);
        n.sort();
        bad += try runProbe("LmsSecretKey.sign (h5/w4, leaf 3)", callLmsSign, n, null);
    }

    // ── HSS (2 levels): init + first sign (builds the child), and a later sign ──
    const child = childOf(&cur_seed);
    {
        n.reset();
        n.addImage("SEED", &cur_seed);
        n.addImage("child SEED", &child.seed);
        allLeavesNeedles(n, &cur_id, &cur_seed, 0);
        allLeavesNeedles(n, &child.id, &child.seed, 0);
        // The parent's signature of the child's public key (leaf 0): its
        // message is the child's encoded LMS public key, taken from a real run.
        var probe_sk: SecretKey = undefined;
        try skInit(&probe_sk, key_fba.allocator(), &cur_seed);
        defer probe_sk.deinit();
        _ = try probe_sk.sign(message, &sig_buf);
        const child_pk = probe_sk.pubs[1].toBytes();
        otsNeedles(n, ots_set, &cur_id, 0, &cur_seed, &child_pk);
        otsNeedles(n, ots_set, &child.id, 0, &child.seed, message);
        n.sort();
        bad += try runProbe("SecretKey.init + SigningKey.init/sign/deinit (HSS 2 levels, builds child)", callHssBuild, n, &heap_buf);
    }
    try skInit(&hsk_built, key_fba.allocator(), &cur_seed);
    defer hsk_built.deinit();
    _ = try hsk_built.sign(message, &sig_buf); // builds the child tree
    {
        n.reset();
        n.addImage("SEED", &cur_seed);
        n.addImage("child SEED", &child.seed);
        otsNeedles(n, ots_set, &child.id, 0, &child.seed, message);
        n.sort();
        bad += try runProbe("SecretKey.sign (HSS, child built)", callHssSign, n, null);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
