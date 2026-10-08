// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the hybrid envelope's secret paths:
//! `SealRandomness.generate`, `seal`/`open`, `sealStream`/`openStream` and
//! the two key derivations (`deriveKeys`, `deriveStreamKey`). The time secret,
//! tlock's sigma, the KEM message m (the first `security_bytes` of the coins),
//! the KEM shared secret s_pq, the derived AEAD key and nonce, the stream key
//! and the plaintext are needles. Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const tlock = @import("tlock");
const hqc = @import("hqc");
const envelope = @import("envelope.zig");
const stream = @import("stream.zig");

const bls12_381 = tlock.bls12_381;
const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const Fr = bls12_381.Fr;
const Fp12 = bls12_381.Fp12;
const cs = tlock.ciphersuite;
const Kem = hqc.Hqc128;
const Env = envelope.Envelope(Kem);
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
        std.debug.print("\n=== STACKPROBE timelock_envelope: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

fn apiGenerate(out: *Env.SealRandomness, io: std.Io) void {
    out.generate(io);
}
fn apiSeal(gpa: std.mem.Allocator, pt: []const u8, ek: *const Kem.EncapsKey, rnd: *const Env.SealRandomness) []u8 {
    return Env.seal(gpa, pt, ek, beacon_pub, probe_round, rnd) catch unreachable;
}
fn apiOpen(gpa: std.mem.Allocator, env: []const u8, dk: *const Kem.DecapsKey) []u8 {
    return Env.open(gpa, env, dk, round_sig) catch unreachable;
}
fn apiSealStream(gpa: std.mem.Allocator, w: *std.Io.Writer, r: *std.Io.Reader, ek: *const Kem.EncapsKey, rnd: *const Env.SealRandomness) void {
    Env.sealStream(gpa, w, r, ek, beacon_pub, probe_round, rnd) catch unreachable;
}
fn apiOpenStream(gpa: std.mem.Allocator, w: *std.Io.Writer, r: *std.Io.Reader, dk: *const Kem.DecapsKey) void {
    Env.openStream(gpa, w, r, dk, round_sig) catch unreachable;
}
fn apiDeriveKeys(out: *envelope.DerivedKeys, s_time: *const [16]u8, s_pq: *const Kem.SharedSecret) void {
    envelope.deriveKeys(out, s_time, s_pq, Env.suite_id, probe_round);
}
fn apiDeriveStreamKey(out: *[32]u8, s_time: *const [16]u8, s_pq: *const Kem.SharedSecret, th: *const [32]u8) void {
    stream.deriveStreamKey(out, s_time, s_pq, Env.suite_id, probe_round, th);
}

// ── fixtures ────────────────────────────────────────────────────────────────

var nd: Needles = .{};
var cur_seed: [64]u8 = undefined;
var kp: Kem.KeyPair = undefined;
var cur_rnd: Env.SealRandomness = undefined;
var cur_pt: [300]u8 = undefined;
var cur_env: [8192]u8 = undefined;
var cur_env_len: usize = 0;
var cur_wire: [8192]u8 = undefined;
var cur_wire_len: usize = 0;
var cur_s_pq: Kem.SharedSecret = undefined;
var cur_th: [32]u8 = undefined;
var beacon_pub: g2.Affine = undefined;
var round_sig: g1.Affine = undefined;
const probe_round: u64 = 1000;

var heap_buf: [256 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;
var rnd_sink: Env.SealRandomness = undefined;
var keys_sink: envelope.DerivedKeys = undefined;
var key_sink: [32]u8 = undefined;
var out_buf: [8192]u8 = undefined;

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

noinline fn callGenerate() void {
    apiGenerate(&rnd_sink, fakeIo());
    std.mem.doNotOptimizeAway(&rnd_sink);
}
noinline fn callSeal() void {
    heap_fba.reset();
    const e = apiSeal(heap_fba.allocator(), &cur_pt, &kp.ek, &cur_rnd);
    std.mem.doNotOptimizeAway(e.ptr);
}
noinline fn callOpen() void {
    heap_fba.reset();
    const p = apiOpen(heap_fba.allocator(), cur_env[0..cur_env_len], &kp.dk);
    std.mem.doNotOptimizeAway(p.ptr);
}
noinline fn callSealStream() void {
    heap_fba.reset();
    var w: std.Io.Writer = .fixed(&out_buf);
    var r: std.Io.Reader = .fixed(&cur_pt);
    apiSealStream(heap_fba.allocator(), &w, &r, &kp.ek, &cur_rnd);
    std.mem.doNotOptimizeAway(&out_buf);
}
noinline fn callOpenStream() void {
    heap_fba.reset();
    var w: std.Io.Writer = .fixed(&out_buf);
    var r: std.Io.Reader = .fixed(cur_wire[0..cur_wire_len]);
    apiOpenStream(heap_fba.allocator(), &w, &r, &kp.dk);
    std.mem.doNotOptimizeAway(&out_buf);
}
noinline fn callDeriveKeys() void {
    apiDeriveKeys(&keys_sink, &cur_rnd.s_time, &cur_s_pq);
    std.mem.doNotOptimizeAway(&keys_sink);
}
noinline fn callDeriveStreamKey() void {
    apiDeriveStreamKey(&key_sink, &cur_rnd.s_time, &cur_s_pq, &cur_th);
    std.mem.doNotOptimizeAway(&key_sink);
}

test "STACKPROBE: no time secret, sigma, KEM secret, derived key or plaintext residue on the dead stack after the hybrid envelope" {
    try skipUnlessOptimized();
    heap_fba = .init(&heap_buf);
    var bad: usize = 0;
    var beacon_sk_bytes: [32]u8 = undefined;
    Sha256.hash("timelock-envelope-probe-beacon", &beacon_sk_bytes, .{});
    beacon_sk_bytes[0] &= 0x3f;
    const beacon_sk = try Fr.fromBytes(beacon_sk_bytes);
    beacon_pub = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(beacon_sk).toAffine();
    round_sig = g1.Jacobian.fromAffine(cs.h1(cs.beaconId(probe_round))).scalarMul(beacon_sk).toAffine();

    for (0..2) |ci| {
        const c: u8 = @intCast(ci);
        Sha256.hash(&[_]u8{ 't', 'e', '-', 's', c }, cur_seed[0..32], .{});
        Sha256.hash(cur_seed[0..32], cur_seed[32..64], .{});
        var kseed: [32]u8 = undefined;
        Sha256.hash(&[_]u8{ 't', 'e', '-', 'k', c }, &kseed, .{});
        Kem.keypair(&kp, &kseed);
        for (&cur_pt, 0..) |*b, i| b.* = cur_seed[i % 64] ^ @as(u8, @truncate(i * 37));
        apiGenerate(&cur_rnd, fakeIo());
        var enc_ct: Kem.Ciphertext = undefined;
        Kem.encaps(&enc_ct, &cur_s_pq, &kp.ek, &cur_rnd.kem_coins);
        var keys: envelope.DerivedKeys = undefined;
        apiDeriveKeys(&keys, &cur_rnd.s_time, &cur_s_pq);

        heap_fba.reset();
        const env = apiSeal(heap_fba.allocator(), &cur_pt, &kp.ek, &cur_rnd);
        @memcpy(cur_env[0..env.len], env);
        cur_env_len = env.len;
        {
            var w: std.Io.Writer = .fixed(&cur_wire);
            var r: std.Io.Reader = .fixed(&cur_pt);
            heap_fba.reset();
            apiSealStream(heap_fba.allocator(), &w, &r, &kp.ek, &cur_rnd);
            cur_wire_len = w.end;
        }
        Sha256.hash(cur_wire[0..stream.Stream(Kem).prefix_bytes], &cur_th, .{});
        var skey: [32]u8 = undefined;
        apiDeriveStreamKey(&skey, &cur_rnd.s_time, &cur_s_pq, &cur_th);

        nd.reset();
        nd.addBoth("s_time", &cur_rnd.s_time);
        nd.addBoth("sigma", &cur_rnd.tlock_sigma);
        nd.addBoth("KEM m", cur_rnd.kem_coins[0..Kem.security_bytes]);
        nd.addBoth("s_pq", &cur_s_pq);
        nd.addBoth("AEAD key", &keys.key);
        nd.addBoth("stream key", &skey);
        nd.addImage("plaintext", &cur_pt);
        nd.sort();
        leak_src = cur_s_pq;
        bad += try runProbe("seal", callSeal, &nd);
        bad += try runProbe("open", callOpen, &nd);
        bad += try runProbe("sealStream", callSealStream, &nd);
        bad += try runProbe("openStream", callOpenStream, &nd);
        bad += try runProbe("deriveKeys", callDeriveKeys, &nd);
        bad += try runProbe("deriveStreamKey", callDeriveStreamKey, &nd);

        nd.reset();
        nd.addBoth("rng", cur_seed[0..32]);
        nd.addBoth("rng", cur_seed[32..64]);
        nd.sort();
        leak_src = cur_seed[0..32].*;
        bad += try runProbe("SealRandomness.generate", callGenerate, &nd);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
