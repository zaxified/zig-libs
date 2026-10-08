// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every tlock entry point that holds a secret:
//! the BF-IBE core (`encrypt`: the message, sigma, the FO scalar r, the
//! pairing value and both masks; `decrypt`: the same, recovered), the age
//! layer (`age.encrypt`/`age.decrypt`: the file key, the header-MAC and
//! payload keys, the plaintext; `sealPayload`/`openPayload`;
//! `PayloadStream.init`; `Randomness.draw`) and `ciphersuite.randomSigma`.
//! The round signature is NOT a secret (the beacon publishes it). Kept in the
//! module per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! The pairing value is recomputed from the ciphertext (`e(σ_round, U)`, the
//! decryptor's route) in both the canonical and drand's cubed representation
//! (`h2` hashes the cube). Windows with fewer than 8 distinct bytes are
//! skipped.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const bls12_381 = @import("bls12_381");
const tlock = @import("tlock.zig");
const age = @import("age.zig");
const cs = @import("ciphersuite.zig");

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const Fr = bls12_381.Fr;
const Fp12 = bls12_381.Fp12;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const B = cs.block_bytes;

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
    fn addG1(self: *Needles, name: []const u8, p: g1.Affine) void {
        self.addImage(name, std.mem.asBytes(&p));
        self.addBoth(name, &g1.toBytesCompressed(p));
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
        std.debug.print("\n=== STACKPROBE tlock: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

fn apiEncrypt(pub_key: g2.Affine, rnd_round: u64, m: *const [B]u8, sigma: *const [B]u8) tlock.Ciphertext {
    return tlock.encrypt(pub_key, rnd_round, m, sigma);
}
fn apiDecrypt(out: *[B]u8, sig: g1.Affine, ct: tlock.Ciphertext) void {
    tlock.decrypt(out, sig, ct) catch unreachable;
}
fn apiRandomSigma(out: *[B]u8, io: std.Io) void {
    cs.randomSigma(out, io);
}
fn apiDraw(out: *age.Randomness, io: std.Io) void {
    age.Randomness.draw(out, io);
}
fn apiAgeEncrypt(out: []u8, pt: []const u8, pub_key: g2.Affine, rnd_round: u64, rnd: *const age.Randomness) []u8 {
    return age.encrypt(out, pt, pub_key, rnd_round, chain_hash, rnd) catch unreachable;
}
fn apiAgeDecrypt(out: []u8, file: []const u8, sig: g1.Affine) []u8 {
    return age.decrypt(out, file, sig, .{}) catch unreachable;
}
fn apiSeal(out: []u8, key: *const [32]u8, pt: []const u8) void {
    age.sealPayload(out, key, pt);
}
fn apiOpen(out: []u8, key: *const [32]u8, sealed: []const u8) void {
    age.openPayload(out, key, sealed) catch unreachable;
}
fn apiStreamInit(out: *age.PayloadStream, key: *const [32]u8) void {
    out.init(key);
}

// ── fixtures ────────────────────────────────────────────────────────────────

var nd: Needles = .{};
var cur_seed: [64]u8 = undefined;
var cur_msg: [B]u8 = undefined;
var cur_sigma: [B]u8 = undefined;
var cur_ct: tlock.Ciphertext = undefined;
var cur_rnd: age.Randomness = undefined;
var cur_key: [32]u8 = undefined;
var cur_pt: [200]u8 = undefined;
var cur_file: [1024]u8 = undefined;
var cur_file_len: usize = 0;
var cur_sealed: [age.sealedLen(200)]u8 = undefined;
var beacon_pub: g2.Affine = undefined;
var round_sig: g1.Affine = undefined;
const probe_round: u64 = 1000;
const chain_hash: [32]u8 = @splat(0x5c);

var ct_sink: tlock.Ciphertext = undefined;
var block_sink: [B]u8 = undefined;
var rnd_sink: age.Randomness = undefined;
var stream_sink: age.PayloadStream = undefined;
var file_sink: [1024]u8 = undefined;
var pt_sink: [200]u8 = undefined;
var sealed_sink: [age.sealedLen(200)]u8 = undefined;

var fake_vtable: std.Io.VTable = undefined;
fn fakeRandomSecure(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    for (buffer, 0..) |*b, i| b.* = cur_seed[i % cur_seed.len];
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

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

noinline fn callEncrypt() void {
    ct_sink = apiEncrypt(beacon_pub, probe_round, &cur_msg, &cur_sigma);
    std.mem.doNotOptimizeAway(&ct_sink);
}
noinline fn callDecrypt() void {
    apiDecrypt(&block_sink, round_sig, cur_ct);
    std.mem.doNotOptimizeAway(&block_sink);
}
noinline fn callRandomSigma() void {
    apiRandomSigma(&block_sink, fakeIo());
    std.mem.doNotOptimizeAway(&block_sink);
}
noinline fn callDraw() void {
    apiDraw(&rnd_sink, fakeIo());
    std.mem.doNotOptimizeAway(&rnd_sink);
}
noinline fn callAgeEncrypt() void {
    const f = apiAgeEncrypt(&file_sink, &cur_pt, beacon_pub, probe_round, &cur_rnd);
    std.mem.doNotOptimizeAway(f.ptr);
}
noinline fn callAgeDecrypt() void {
    const p = apiAgeDecrypt(&pt_sink, cur_file[0..cur_file_len], round_sig);
    std.mem.doNotOptimizeAway(p.ptr);
}
noinline fn callSeal() void {
    apiSeal(&sealed_sink, &cur_key, &cur_pt);
    std.mem.doNotOptimizeAway(&sealed_sink);
}
noinline fn callOpen() void {
    apiOpen(&pt_sink, &cur_key, &cur_sealed);
    std.mem.doNotOptimizeAway(&pt_sink);
}
noinline fn callStreamInit() void {
    apiStreamInit(&stream_sink, &cur_key);
    std.mem.doNotOptimizeAway(&stream_sink);
}

// ── needles ─────────────────────────────────────────────────────────────────

/// Everything the BF-IBE core holds for the ciphertext of `m` under `sigma`.
fn coreNeedles(n: *Needles, m: *const [B]u8, sigma: *const [B]u8, ct: tlock.Ciphertext) void {
    n.addBoth("message", m);
    n.addBoth("sigma", sigma);
    n.addFr("r", cs.h3(sigma, m));
    const gt = bls12_381.pairing.pairing(round_sig, ct.u);
    n.addImage("Gid^r", std.mem.asBytes(&gt));
    const cube = gt.square().mul(gt);
    n.addImage("Gid^r (drand)", std.mem.asBytes(&cube));
    var mask_v: [B]u8 = undefined;
    for (&mask_v, ct.v, sigma) |*o, v, s| o.* = v ^ s;
    n.addBoth("H2 mask", &mask_v);
    var mask_w: [B]u8 = undefined;
    for (&mask_w, ct.w, m) |*o, w, x| o.* = w ^ x;
    n.addBoth("H4 mask", &mask_w);
}

/// age's key schedule from the file key: the header-MAC key and (for
/// `nonce`) the payload key.
fn keyScheduleNeedles(n: *Needles, file_key: *const [16]u8, nonce: *const [16]u8) void {
    n.addBoth("file key", file_key);
    var hk: [32]u8 = undefined;
    Hkdf.expand(&hk, "header", Hkdf.extract("", file_key));
    n.addBoth("header MAC key", &hk);
    var pk: [32]u8 = undefined;
    Hkdf.expand(&pk, "payload", Hkdf.extract(nonce, file_key));
    n.addBoth("payload key", &pk);
}

test "STACKPROBE: no message, sigma, r, pairing value, file/payload key or plaintext residue on the dead stack after tlock" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    // A beacon of our own: sk, beacon_pub = sk·G2, the probe_round signature sk·H1(probe_round).
    var beacon_sk_bytes: [32]u8 = undefined;
    Sha256.hash("tlock-probe-beacon", &beacon_sk_bytes, .{});
    beacon_sk_bytes[0] &= 0x3f;
    const beacon_sk = try Fr.fromBytes(beacon_sk_bytes);
    beacon_pub = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(beacon_sk).toAffine();
    round_sig = g1.Jacobian.fromAffine(cs.h1(cs.beaconId(probe_round))).scalarMul(beacon_sk).toAffine();

    for (0..2) |ci| {
        const c: u8 = @intCast(ci);
        Sha256.hash(&[_]u8{ 't', 'l', '-', 's', c }, cur_seed[0..32], .{});
        Sha256.hash(cur_seed[0..32], cur_seed[32..64], .{});
        var h: [32]u8 = undefined;
        Sha256.hash(&[_]u8{ 't', 'l', '-', 'm', c }, &h, .{});
        cur_msg = h[0..B].*;
        Sha256.hash(&[_]u8{ 't', 'l', '-', 'g', c }, &h, .{});
        cur_sigma = h[0..B].*;
        for (&cur_pt, 0..) |*b, i| b.* = cur_seed[i % 64] ^ @as(u8, @truncate(i * 31));
        Sha256.hash(&[_]u8{ 't', 'l', '-', 'k', c }, &cur_key, .{});
        cur_ct = apiEncrypt(beacon_pub, probe_round, &cur_msg, &cur_sigma);

        // BF-IBE core.
        nd.reset();
        coreNeedles(&nd, &cur_msg, &cur_sigma, cur_ct);
        nd.sort();
        leak_src = (cur_msg ++ cur_sigma);
        bad += try runProbe("encrypt", callEncrypt, &nd);
        bad += try runProbe("decrypt", callDecrypt, &nd);

        nd.reset();
        nd.addBoth("rng", cur_seed[0..32]);
        nd.addBoth("rng", cur_seed[32..64]);
        nd.sort();
        leak_src = cur_seed[0..32].*;
        bad += try runProbe("ciphersuite.randomSigma", callRandomSigma, &nd);
        bad += try runProbe("age.Randomness.draw", callDraw, &nd);

        // age, whole file.
        apiDraw(&cur_rnd, fakeIo());
        const file = apiAgeEncrypt(&cur_file, &cur_pt, beacon_pub, probe_round, &cur_rnd);
        cur_file_len = file.len;
        const age_ct = (try age.Header.parse(file)).recipient.ciphertext;
        nd.reset();
        keyScheduleNeedles(&nd, &cur_rnd.file_key, &cur_rnd.nonce);
        coreNeedles(&nd, &cur_rnd.file_key, &cur_rnd.sigma, age_ct);
        nd.addImage("plaintext", &cur_pt);
        nd.sort();
        leak_src = cur_pt[0..LEAK].*;
        bad += try runProbe("age.encrypt", callAgeEncrypt, &nd);
        bad += try runProbe("age.decrypt", callAgeDecrypt, &nd);

        // age, payload layer on its own.
        apiSeal(&cur_sealed, &cur_key, &cur_pt);
        nd.reset();
        nd.addBoth("key", &cur_key);
        nd.addImage("plaintext", &cur_pt);
        nd.sort();
        leak_src = cur_key;
        bad += try runProbe("age.sealPayload", callSeal, &nd);
        bad += try runProbe("age.openPayload", callOpen, &nd);
        bad += try runProbe("age.PayloadStream.init", callStreamInit, &nd);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
