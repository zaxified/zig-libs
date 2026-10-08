// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the HQC-KEM entry points: `keypair` (the
//! seed, the PKE seed and sigma it expands to), `encaps` (the message m, the
//! shared secret K and the PKE randomness seed theta) and `decaps` (the
//! secret half of dk, the re-derived m', K', theta', the implicit-rejection
//! key K_bar and the result). Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! The values are recomputed with the module's own hashes (`prng.hashG`,
//! `hashH`, `hashJ`, the seed Xof). The sparse secret vectors x, y, r1, r2, e
//! are not needles: almost every 16-byte window of them is zero and the
//! scan skips windows with fewer than 8 distinct bytes.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const params = @import("params.zig");
const prng = @import("prng.zig");
const root = @import("root.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

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
        var r: [1024]u8 = undefined;
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
        std.debug.print("\n=== STACKPROBE hqc: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<14} {d} (5 calls)\n", .{ name, total[i] });
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

// ── API adapter: the only place that names the shapes under test ────────────
// (BEFORE the 2026-10-09 fix these took and returned the secrets by value.)

fn apiKeypair(comptime K: type, out: *K.KeyPair, seed: *const [params.seed_bytes]u8) void {
    K.keypair(out, seed);
}
fn apiEncaps(comptime K: type, ct: *K.Ciphertext, ss: *K.SharedSecret, ek: *const K.EncapsKey, coins: *const [K.coins_bytes]u8) void {
    K.encaps(ct, ss, ek, coins);
}
fn apiDecaps(comptime K: type, ss: *K.SharedSecret, dk: *const K.DecapsKey, ct: *const K.Ciphertext) void {
    K.decaps(ss, dk, ct);
}

var nd: Needles = .{};

fn Harness(comptime K: type) type {
    return struct {
        var seed: [params.seed_bytes]u8 = undefined;
        var coins: [K.coins_bytes]u8 = undefined;
        var kp: K.KeyPair = undefined;
        var ct: K.Ciphertext = undefined;
        var ss: K.SharedSecret = undefined;
        var kp_sink: K.KeyPair = undefined;
        var ct_sink: K.Ciphertext = undefined;
        var ss_sink: K.SharedSecret = undefined;

        noinline fn callKeypair() void {
            apiKeypair(K, &kp_sink, &seed);
            std.mem.doNotOptimizeAway(&kp_sink);
        }
        noinline fn callEncaps() void {
            apiEncaps(K, &ct_sink, &ss_sink, &kp.ek, &coins);
            std.mem.doNotOptimizeAway(&ss_sink);
        }
        noinline fn callDecaps() void {
            apiDecaps(K, &ss_sink, &kp.dk, &ct);
            std.mem.doNotOptimizeAway(&ss_sink);
        }

        fn run(comptime label: []const u8, case: u8) !usize {
            var bad: usize = 0;
            Sha256.hash(&[_]u8{ 'h', 'q', 'c', '-', 's', case }, &seed, .{});
            var cw: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash(&[_]u8{ 'h', 'q', 'c', '-', 'c', case }, &cw, .{});
            coins = cw[0..K.coins_bytes].*;
            apiKeypair(K, &kp, &seed);
            apiEncaps(K, &ct, &ss, &kp.ek, &coins);

            // keypair: the seed, the PKE seed and sigma it expands to, and
            // the secret tail of dk (dk_pke || sigma || seed).
            var xof = prng.Xof.init(&seed);
            var seed_pke: [params.seed_bytes]u8 = undefined;
            xof.getBytes(&seed_pke);
            var sigma: [K.security_bytes]u8 = undefined;
            xof.getBytes(&sigma);
            nd.reset();
            nd.addBoth("seed", &seed);
            nd.addBoth("seed_pke", &seed_pke);
            nd.addBoth("sigma", &sigma);
            nd.addImage("dk secret half", kp.dk[K.ek_bytes..]);
            nd.sort();
            leak_src = seed;
            bad += try runProbe(label ++ " keypair", callKeypair, &nd);

            // encaps / decaps: m, K, theta, K_bar, and the secret half of dk.
            var h_ek: [32]u8 = undefined;
            prng.hashH(&h_ek, &kp.ek);
            const m = coins[0..K.security_bytes];
            const salt = coins[K.security_bytes..];
            var k_theta: [64]u8 = undefined;
            prng.hashG(&k_theta, &h_ek, m, salt);
            var k_bar: [32]u8 = undefined;
            prng.hashJ(&k_bar, &h_ek, &sigma, &ct);
            nd.reset();
            nd.addBoth("m", m);
            nd.addBoth("K", k_theta[0..32]);
            nd.addBoth("theta", k_theta[32..64]);
            nd.addBoth("K_bar", &k_bar);
            nd.addBoth("seed_pke", &seed_pke);
            nd.addBoth("sigma", &sigma);
            nd.sort();
            leak_src = k_theta[0..32].*;
            bad += try runProbe(label ++ " encaps", callEncaps, &nd);
            bad += try runProbe(label ++ " decaps", callDecaps, &nd);
            return bad;
        }
    };
}

test "STACKPROBE: no seed, sigma, m, K, theta or K_bar residue on the dead stack after HQC-KEM" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..2) |ci| {
        const c: u8 = @intCast(ci);
        bad += try Harness(root.Hqc128).run("hqc-128", c);
        bad += try Harness(root.Hqc192).run("hqc-192", c);
        bad += try Harness(root.Hqc256).run("hqc-256", c);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
