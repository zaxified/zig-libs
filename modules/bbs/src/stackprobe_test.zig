// SPDX-License-Identifier: MIT

//! Dead-stack and freed-heap residue probe for every BBS entry point that
//! holds a secret: `keyGen` (SK, the key material), `skToPk` (SK), `sign` (SK,
//! the undisclosed-or-not message scalars, `1/(SK+e)`, the hash input
//! `SK || msgs`), `calculateRandomScalars` (the raw entropy and the reduced
//! scalars) and `proofGen` (every blinding scalar `r1, r2, e~, r1~, r3~, m~_j`,
//! `r3 = 1/r2`, `r1*r2`, the signature's `A` and `e`, the undisclosed messages'
//! scalars). Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets. The heap
//! is a static arena zeroed before each call and scanned afterwards, whole, so
//! a buffer the library freed unwiped is found too. ReleaseFast / ReleaseSmall
//! only — Debug and ReleaseSafe fill `undefined` with 0xaa, so the scan cannot
//! see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in; windows
//! with fewer than 8 distinct bytes are skipped. NOT built: `e` of `sign`
//! (it is the second half of the signature the call returns — public by
//! design, it would only ever hit as the returned copy) and the internal
//! `expand_message` blocks (not recomputable through the public API; they are
//! covered by the burn, not by a needle).
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const bbs = @import("bbs.zig");
const keys = @import("keys.zig");
const cs = @import("ciphersuite.zig");

const G1 = cs.G1;
const Fr = cs.Fr;
const S = cs.Sha256;
const Scheme = bbs.sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const sig_len = bbs.Signature.encoded_bytes;

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
    fn addG1(self: *Needles, name: []const u8, p: G1.Affine) void {
        self.addImage(name, std.mem.asBytes(&p));
        self.addBoth(name, &G1.toBytesCompressed(p));
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

// ── the heap: a static arena, zeroed before a call, scanned whole after it ──

var arena_buf: [256 * 1024]u8 align(16) = undefined;
var arena: std.heap.FixedBufferAllocator = undefined;

fn clearHeap() void {
    @memset(&arena_buf, 0);
    arena = std.heap.FixedBufferAllocator.init(&arena_buf);
}

fn scanHeap(needles: *const Needles) Hits {
    var hits: Hits = @splat(0);
    var skip_until: usize = 0;
    var i: usize = 0;
    while (i + W <= arena_buf.len) : (i += 1) {
        if (i < skip_until) continue;
        if (needles.find(std.mem.readInt(u128, arena_buf[i..][0..W], .little))) |id| {
            hits[id] += 1;
            skip_until = i + W;
        }
    }
    return hits;
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

var heap_hits: Hits = @splat(0);

/// `inline`: as its own frame it ran the call deeper than the region top
/// `runProbe` computed (acme, 2026-10-08).
inline fn measure(call: *const fn () void, n: *const Needles) Hits {
    clearHeap();
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    const stack_hits = scan(n);
    heap_hits = scanHeap(n);
    return stack_hits;
}

fn runProbe(label: []const u8, call: *const fn () void, n: *const Needles) !usize {
    region_hi = stackHere() - PAD;
    region_lo = region_hi - WINDOW;

    const neg = measure(callInnocent, n);
    const pos = measure(callLeaky, n);

    var total: Hits = @splat(0);
    var heap_total: Hits = @splat(0);
    var shallowest: usize = 0;
    var deepest: usize = 0;
    for (0..5) |_| {
        for (&total, measure(call, n)) |*t, x| t.* += x;
        for (&heap_total, heap_hits) |*t, x| t.* += x;
        if (hit_min_depth != 0 and (shallowest == 0 or hit_min_depth < shallowest)) shallowest = hit_min_depth;
        if (hit_max_depth > deepest) deepest = hit_max_depth;
    }
    clearHeap();
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    const depth = dirtyDepth();

    var sum: usize = 0;
    for (total) |h| sum += h;
    var heap_sum: usize = 0;
    for (heap_total) |h| heap_sum += h;
    var neg_sum: usize = 0;
    for (neg) |h| neg_sum += h;
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or heap_sum != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE bbs: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B heap={d} ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth, heap_sum });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<14} {d} (5 calls)\n", .{ name, total[i] });
            if (heap_total[i] != 0) std.debug.print("    HEAP    {s:<14} {d} (5 calls)\n", .{ name, heap_total[i] });
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

// ── API adapter: the only place that names the shapes under test ────────────
// (BEFORE the 2026-10-09 fix these took and returned the secrets by value.)
// `keyGen` used to return the key, `sign`/`proofGen` took it and the
// signature by value, `calculateRandomScalars` returned its array.

const n_msgs = 4;
const n_rs = bbs.randomScalarCount(n_msgs - 2); // two disclosed

fn apiKeyGen(out: *keys.SecretKey, km: []const u8, ki: []const u8) void {
    keys.keyGen(out, km, ki, null) catch unreachable;
}
fn apiSkToPk(out: *keys.PublicKey, sk: *const keys.SecretKey) void {
    out.* = keys.skToPk(sk);
}
fn apiSign(out: *[sig_len]u8, a: std.mem.Allocator, sk: *const keys.SecretKey, pk: keys.PublicKey, header: []const u8, msgs: []const []const u8) void {
    out.* = Scheme.sign(a, sk, pk, header, msgs) catch unreachable;
}
fn apiRandomScalars(out: *[n_rs]Fr, io: std.Io) void {
    cs.calculateRandomScalars(out, io);
}
fn apiProofGen(a: std.mem.Allocator, pk: keys.PublicKey, sig: *const [sig_len]u8, header: []const u8, ph: []const u8, msgs: []const []const u8, disclosed: []const usize, rs: []const Fr) []u8 {
    return Scheme.proofGen(a, pk, sig, header, ph, msgs, disclosed, rs) catch unreachable;
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

var nd: Needles = .{};
var cur_km: [64]u8 = undefined;
const probe_info = "bbs-probe-info";
var cur_sk: keys.SecretKey = undefined;
var cur_pk: keys.PublicKey = undefined;
var cur_msgs: [n_msgs][32]u8 = undefined;
var cur_slices: [n_msgs][]const u8 = undefined;
const probe_header = "bbs-probe-header";
const probe_ph = "bbs-probe-ph";
const disclosed_idx = [_]usize{ 0, 2 };
var cur_sig: [sig_len]u8 = undefined;
var cur_rs: [n_rs]Fr = undefined;
var cur_seed: [1024]u8 = undefined;
var seed_pos: usize = 0;
var sk_sink: keys.SecretKey = undefined;
var pk_sink: keys.PublicKey = undefined;
var sig_sink: [sig_len]u8 = undefined;
var rs_sink: [n_rs]Fr = undefined;
var proof_sink: []u8 = undefined;

/// An `Io` whose secure random replays the case's seed stream, so
/// `calculateRandomScalars` draws known values. Everything else is
/// `std.Io.failing`'s.
var fake_vtable: std.Io.VTable = undefined;
fn fakeRandomSecure(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    for (buffer) |*b| {
        b.* = cur_seed[seed_pos % cur_seed.len];
        seed_pos += 1;
    }
}
fn fakeSwapCancelProtection(_: ?*anyopaque, _: std.Io.CancelProtection) std.Io.CancelProtection {
    return .unblocked;
}
fn fakeIo() std.Io {
    fake_vtable = std.Io.failing.vtable.*;
    fake_vtable.randomSecure = fakeRandomSecure;
    fake_vtable.swapCancelProtection = fakeSwapCancelProtection;
    return .{ .userdata = null, .vtable = &fake_vtable };
}

noinline fn callKeyGen() void {
    apiKeyGen(&sk_sink, &cur_km, probe_info);
    std.mem.doNotOptimizeAway(&sk_sink);
}
noinline fn callSkToPk() void {
    apiSkToPk(&pk_sink, &cur_sk);
    std.mem.doNotOptimizeAway(&pk_sink);
}
noinline fn callSign() void {
    apiSign(&sig_sink, arena.allocator(), &cur_sk, cur_pk, probe_header, &cur_slices);
    std.mem.doNotOptimizeAway(&sig_sink);
}
noinline fn callRandomScalars() void {
    seed_pos = 0;
    apiRandomScalars(&rs_sink, fakeIo());
    std.mem.doNotOptimizeAway(&rs_sink);
}
noinline fn callProofGen() void {
    proof_sink = apiProofGen(arena.allocator(), cur_pk, &cur_sig, probe_header, probe_ph, &cur_slices, &disclosed_idx, &cur_rs);
    std.mem.doNotOptimizeAway(&proof_sink);
}

fn undisclosedScalars(out: *[n_msgs - 2]Fr) !void {
    const scalars = try S.messagesToScalars(std.testing.allocator, &cur_slices);
    defer std.testing.allocator.free(scalars);
    out[0] = scalars[1];
    out[1] = scalars[3];
}

fn signNeedles(n: *Needles) !void {
    n.addFr("sk", cur_sk.scalar);
    const sig = try bbs.Signature.fromBytes(cur_sig);
    const inv = try cur_sk.scalar.add(sig.e).inv();
    n.addFr("1/(sk+e)", inv);
    const scalars = try S.messagesToScalars(std.testing.allocator, &cur_slices);
    defer std.testing.allocator.free(scalars);
    var e_input: [32 * (1 + n_msgs)]u8 = undefined;
    e_input[0..32].* = cur_sk.scalar.toBytes();
    for (scalars, 0..) |m, i| {
        n.addFr("msg scalar", m);
        e_input[32 * (1 + i) ..][0..32].* = m.toBytes();
    }
    n.addBoth("e input", &e_input);
    for (&cur_msgs) |*m| n.addBoth("msg bytes", m);
}

fn proofGenNeedles(n: *Needles) !void {
    const names = [_][]const u8{ "r1", "r2", "e~", "r1~", "r3~", "m~", "m~" };
    for (cur_rs, names) |r, name| n.addFr(name, r);
    n.addFr("r3=1/r2", try cur_rs[1].inv());
    n.addFr("r1*r2", cur_rs[0].mul(cur_rs[1]));
    const sig = try bbs.Signature.fromBytes(cur_sig);
    n.addFr("sig e", sig.e);
    n.addG1("sig A", sig.a);
    var und: [n_msgs - 2]Fr = undefined;
    try undisclosedScalars(&und);
    for (und) |m| n.addFr("undisclosed", m);
    n.addBoth("msg bytes", &cur_msgs[1]);
    n.addBoth("msg bytes", &cur_msgs[3]);
}

test "STACKPROBE: no SK, e, 1/(SK+e), message scalar, blinding scalar or key material residue on the dead stack or in freed heap after BBS" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..2) |ci| {
        const tag: u8 = @intCast(ci);
        Sha256.hash(&[_]u8{ 'b', 'b', 's', '-', 'k', tag }, cur_km[0..32], .{});
        Sha256.hash(cur_km[0..32], cur_km[32..64], .{});
        for (&cur_msgs, 0..) |*m, i| {
            Sha256.hash(&[_]u8{ 'b', 'b', 's', '-', 'm', tag, @intCast(i) }, m, .{});
        }
        for (&cur_slices, &cur_msgs) |*s, *m| s.* = m;
        var chain: [32]u8 = undefined;
        Sha256.hash(&[_]u8{ 'b', 'b', 's', '-', 'r', tag }, &chain, .{});
        for (0..cur_seed.len / 32) |i| {
            cur_seed[i * 32 ..][0..32].* = chain;
            Sha256.hash(&chain, &chain, .{});
        }

        apiKeyGen(&cur_sk, &cur_km, probe_info);
        apiSkToPk(&cur_pk, &cur_sk);
        clearHeap();
        apiSign(&cur_sig, arena.allocator(), &cur_sk, cur_pk, probe_header, &cur_slices);
        seed_pos = 0;
        apiRandomScalars(&cur_rs, fakeIo());

        nd.reset();
        nd.addFr("sk", cur_sk.scalar);
        nd.addBoth("key material", &cur_km);
        var derive: [64 + 2]u8 = undefined;
        derive[0..64].* = cur_km;
        std.mem.writeInt(u16, derive[64..], probe_info.len, .big);
        nd.addImage("derive input", &derive);
        nd.sort();
        leak_src = cur_sk.scalar.toBytes();
        bad += try runProbe("keyGen", callKeyGen, &nd);

        nd.reset();
        nd.addFr("sk", cur_sk.scalar);
        nd.sort();
        bad += try runProbe("skToPk", callSkToPk, &nd);

        nd.reset();
        try signNeedles(&nd);
        nd.sort();
        bad += try runProbe("sign", callSign, &nd);

        nd.reset();
        nd.addBoth("rng seed", cur_seed[0 .. 48 * n_rs]);
        for (cur_rs) |r| nd.addFr("scalar", r);
        nd.sort();
        leak_src = cur_seed[0..32].*;
        bad += try runProbe("randomScalars", callRandomScalars, &nd);

        nd.reset();
        try proofGenNeedles(&nd);
        nd.sort();
        leak_src = cur_rs[0].toBytes();
        bad += try runProbe("proofGen", callProofGen, &nd);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
