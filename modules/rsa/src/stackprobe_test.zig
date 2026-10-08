// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the private-key paths: `signPkcs1v15`,
//! `signPss`, `decryptOaep` and key loading (`SecretKey.fromPrimes`, which
//! `fromDer`/`fromPem`/`fromPkcs8` all route through). Kept in the module per
//! `CONVENTIONS.md` §9. Engine and method as `ed448`'s `stackprobe_test.zig`:
//! paint, call, scan every 16-byte window of every secret image, next to a
//! NEGATIVE and a POSITIVE control. ReleaseFast/ReleaseSmall only.
//!
//! Needles: `p`, `q`, `d`, `dP`, `dQ`, `qInv` (big- and little-endian, and
//! the in-memory images of the key's `std.crypto.ff` and montint carriers,
//! whose limb layouts differ from the byte strings), and the CRT halves of
//! the operation — `x mod p`, `x mod q` for the signature or plaintext `x` —
//! each of which yields `p` by a gcd with `n`. Low-entropy windows (limb
//! padding) are skipped.

const std = @import("std");
const builtin = @import("builtin");
const rsa = @import("root.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Shake256 = std.crypto.hash.sha3.Shake256;

const WINDOW = 512 * 1024;
const LEAK = 128;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

/// Audit-local keys (not from any vector): SHAKE of a label, so no 16-byte
/// window of them is a run of zeros or of paint that a dead stack holds anyway.
fn caseBytes(comptime n: usize, label: u8, i: u8) [n]u8 {
    var out: [n]u8 = undefined;
    Shake256.hash(&[_]u8{ 'r', 's', 'a', '-', '-', label, i }, &out, .{});
    return out;
}
const n_cases = 2;

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
            // Skip low-entropy windows (limb padding, short values' zero
            // high limbs): a dead stack holds runs like that anyway.
            if (distinct(image[i..][0..W]) < 8) continue;
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
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
        std.debug.print("\n=== STACKPROBE rsa: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

/// The module's own 2048-bit KAT key (`root.zig` `kat2048`; OpenSSL-made,
/// public in this repository, never a real key).
const kat_p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
const kat_q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
const kat_n = hexLit("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");
const kat_e = [_]u8{ 0x01, 0x00, 0x01 };

fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const msg = "rsa dead-stack probe message";
var cur_sk: rsa.SecretKey = undefined;
var cur_pk: rsa.PublicKey = undefined;
var cur_ct: [256]u8 = undefined;
var out_buf: [512]u8 = undefined;
var pss_prng: std.Random.DefaultPrng = undefined;

noinline fn callSignPkcs1v15() void {
    const s = rsa.signPkcs1v15(&cur_sk, Sha256, msg, &out_buf) catch unreachable;
    std.mem.doNotOptimizeAway(s.ptr);
}
noinline fn callSignPss() void {
    pss_prng = .init(7);
    const s = rsa.signPss(&cur_sk, Sha256, pss_prng.random(), msg, 32, &out_buf) catch unreachable;
    std.mem.doNotOptimizeAway(s.ptr);
}
noinline fn callDecryptOaep() void {
    const m = rsa.decryptOaep(&cur_sk, Sha256, &cur_ct, "", &out_buf) catch unreachable;
    std.mem.doNotOptimizeAway(m.ptr);
}
noinline fn callFromPrimes() void {
    var sk: rsa.SecretKey = undefined;
    rsa.SecretKey.fromPrimes(&sk, &kat_p, &kat_q, &kat_e) catch unreachable;
    std.mem.doNotOptimizeAway(&sk.n);
    sk.deinit();
}

fn addBig(n: *Needles, name: []const u8, comptime len: usize, be: [len]u8) void {
    n.addImage(name, &be);
    var le = be;
    std.mem.reverse(u8, &le);
    n.addImage(name, &le);
}

fn feBytes(fe: rsa.Fe, comptime len: usize) [len]u8 {
    var out: [len]u8 = undefined;
    fe.toBytes(&out, .big) catch unreachable;
    return out;
}

fn keyNeedles(n: *Needles) void {
    addBig(n, "p", 128, kat_p);
    addBig(n, "q", 128, kat_q);
    addBig(n, "d", 256, feBytes(cur_sk.d, 256));
    addBig(n, "dP", 128, feBytes(cur_sk.dp, 128));
    addBig(n, "dQ", 128, feBytes(cur_sk.dq, 128));
    addBig(n, "qInv", 128, feBytes(cur_sk.qinv, 128));
    n.addImage("p (ff image)", std.mem.asBytes(&cur_sk.p));
    n.addImage("q (ff image)", std.mem.asBytes(&cur_sk.q));
    n.addImage("d (ff image)", std.mem.asBytes(&cur_sk.d));
    n.addImage("dP (ff image)", std.mem.asBytes(&cur_sk.dp));
    n.addImage("dQ (ff image)", std.mem.asBytes(&cur_sk.dq));
    n.addImage("qInv (ff image)", std.mem.asBytes(&cur_sk.qinv));
    n.addImage("p (montint)", std.mem.asBytes(&cur_sk.p_mont));
    n.addImage("q (montint)", std.mem.asBytes(&cur_sk.q_mont));
}

/// `x mod p`, `x mod q` for a 2048-bit big-endian `x`.
fn crtHalves(n: *Needles, x: *const [256]u8) void {
    const xi = std.mem.readInt(u2048, x, .big);
    const pi: u2048 = std.mem.readInt(u1024, &kat_p, .big);
    const qi: u2048 = std.mem.readInt(u1024, &kat_q, .big);
    var b: [128]u8 = undefined;
    std.mem.writeInt(u1024, &b, @intCast(xi % pi), .big);
    addBig(n, "x mod p", 128, b);
    std.mem.writeInt(u1024, &b, @intCast(xi % qi), .big);
    addBig(n, "x mod q", 128, b);
}

test "STACKPROBE: no key or CRT residue on the dead stack after signing, decryption and key loading" {
    try skipUnlessOptimized();
    try rsa.SecretKey.fromPrimes(&cur_sk, &kat_p, &kat_q, &kat_e);
    defer cur_sk.deinit();
    cur_pk = try rsa.PublicKey.fromBytes(&kat_n, &kat_e);
    leak_src = kat_p;
    var bad: usize = 0;

    var n: Needles = .{};
    keyNeedles(&n);
    n.sort();
    bad += try runProbe("SecretKey.fromPrimes", callFromPrimes, &n);

    const s1 = (try rsa.signPkcs1v15(&cur_sk, Sha256, msg, &out_buf))[0..256].*;
    n = .{};
    keyNeedles(&n);
    crtHalves(&n, &s1);
    n.sort();
    bad += try runProbe("signPkcs1v15", callSignPkcs1v15, &n);

    pss_prng = .init(7);
    const s2 = (try rsa.signPss(&cur_sk, Sha256, pss_prng.random(), msg, 32, &out_buf))[0..256].*;
    n = .{};
    keyNeedles(&n);
    crtHalves(&n, &s2);
    n.sort();
    bad += try runProbe("signPss", callSignPss, &n);

    var enc_prng: std.Random.DefaultPrng = .init(9);
    cur_ct = (try rsa.encryptOaep(cur_pk, Sha256, enc_prng.random(), "secret plaintext", "", &out_buf))[0..256].*;
    const m = try rsa.rsadpCrt(256, cur_ct, &cur_sk);
    n = .{};
    keyNeedles(&n);
    crtHalves(&n, &m);
    n.sort();
    bad += try runProbe("decryptOaep", callDecryptOaep, &n);

    try std.testing.expectEqual(@as(usize, 0), bad);
}
