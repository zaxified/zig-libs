// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the secret paths: key generation
//! (`generateKeyPair`), secret-key decoding / re-encoding / public-key
//! recomputation (`SecretKey.fromBytes`, `SigningKey.toSecretKeyBytes`,
//! `SecretKey.publicKey`) and signing (`signRandomized`), for Falcon-512 and
//! Falcon-1024. Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `ssh`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in:
//! - keygen: the 48-byte seed, the first 2 KiB of the SHAKE256 stream it
//!   seeds (the randomness that drew f and g), the encoded secret key, and
//!   f, g, F, G as small-int arrays, as lifted `[0, q)` polynomials, as NTT
//!   forms and as FFT doubles (+ the negated -FFT(f), -FFT(F) the signer uses);
//! - signing: the same key images, the Gram matrix g00/g01/g11 the sampler
//!   builds, the per-signature RNG seed (48 B), the ChaCha seed (56 B), the
//!   ChaCha state/buffer image, and the accepted s1/s2 recomputed from the
//!   signature the call produced.
//! Windows with fewer than 8 distinct bytes are skipped: f and g have small
//! coefficients, so their small-int images are only partly visible; the FFT,
//! NTT and encoded forms carry the entropy.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).
//!
//! One extension over `ssh`'s engine: `pre_fn`, a hook run before the window
//! is painted, reseeds the (caller-owned, static) RNG for every repetition.

const std = @import("std");
const builtin = @import("builtin");
const falcon = @import("root.zig");
const poly = @import("poly.zig");
const fft = @import("fft.zig");
const fpr = @import("fpr.zig");
const gaussian = @import("gaussian.zig");
const sign = @import("sign.zig");
const codec = @import("codec.zig");

const Shake256 = std.crypto.hash.sha3.Shake256;

const WINDOW = 1024 * 1024; // keygen / sign of Falcon-1024 dirty > 128 KiB
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 131072;

const Needles = struct {
    win: [max_windows]u128 = undefined,
    owner: [max_windows]u8 = undefined,
    len: usize = 0,
    names: [32][]const u8 = undefined,
    n_names: usize = 0,

    fn reset(self: *Needles) void {
        self.len = 0;
        self.n_names = 0;
    }

    /// Every `stride`-th window of `image` (stride 8 for double arrays).
    fn addStride(self: *Needles, name: []const u8, image: []const u8, stride: usize) void {
        const id: u8 = @intCast(self.lookupName(name));
        var i: usize = 0;
        while (i + W <= image.len) : (i += stride) {
            if (distinct(image[i..][0..W]) < 8) continue;
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    fn addImage(self: *Needles, name: []const u8, image: []const u8) void {
        self.addStride(name, image, 1);
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
var pre_fn: ?*const fn () void = null;

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

fn scan(n: *const Needles) Hits {
    var hits: Hits = @splat(0);
    hit_min_depth = 0;
    hit_max_depth = 0;
    var skip_until: usize = 0;
    var i: usize = 0;
    while (i + W <= WINDOW) : (i += 1) {
        if (i < skip_until) continue;
        if (n.find(std.mem.readInt(u128, snap[i..][0..W], .little))) |id| {
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
    if (pre_fn) |p| p();
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
    if (pre_fn) |p| p();
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
        std.debug.print("\n=== STACKPROBE falcon: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

// ── one parameter set ───────────────────────────────────────────────────────

fn Suite(comptime is1024: bool) type {
    return struct {
        const Ring = if (is1024) poly.Ring1024 else poly.Ring512;
        const n = Ring.n;
        const logn = Ring.logn;
        const Codec = codec.Codec(Ring);
        const Signer = sign.Signer(Ring);
        const SecretKey = if (is1024) falcon.SecretKey1024 else falcon.SecretKey;
        const PublicKey = if (is1024) falcon.PublicKey1024 else falcon.PublicKey;
        const SigningKey = if (is1024) falcon.SigningKey1024 else falcon.SigningKey;
        const sk_len = SecretKey.encoded_length;
        const sig_cap = if (is1024) falcon.max_sig_field_length_1024 else falcon.max_sig_field_length;

        // The caller's own long-lived storage.
        var cur_seed: [48]u8 = undefined;
        var rng_state: sign.ShakePrng = undefined;
        var cur_sk: SigningKey = undefined; // the signing key `sign` uses
        var cur_bytes: [sk_len]u8 = undefined; // the encoded secret key `decode` reads
        var sk_sink: SigningKey = undefined;
        var pk_sink: PublicKey = undefined;
        var dec_sink: SecretKey = undefined;
        var bytes_sink: [sk_len]u8 = undefined;
        var nonce_sink: [falcon.nonce_length]u8 = undefined;
        var sig_sink: [sig_cap]u8 = undefined;
        var sig_len: usize = 0;
        const msg = "falcon stackprobe message";

        // ── API adapter (the only part that depends on the signatures) ──

        fn reseed() void {
            rng_state.init(&cur_seed);
        }

        noinline fn callKeygen() void {
            (if (is1024) falcon.generateKeyPair1024(rng_state.random(), &sk_sink, &pk_sink) else falcon.generateKeyPair(rng_state.random(), &sk_sink, &pk_sink)) catch unreachable;
            std.mem.doNotOptimizeAway(&sk_sink);
        }

        noinline fn callEncode() void {
            cur_sk.toSecretKeyBytes(&bytes_sink);
            std.mem.doNotOptimizeAway(&bytes_sink);
        }

        noinline fn callDecode() void {
            SecretKey.fromBytes(&dec_sink, &cur_bytes) catch unreachable;
            std.mem.doNotOptimizeAway(&dec_sink);
        }

        noinline fn callPublicKey() void {
            pk_sink = dec_sink.publicKey() catch unreachable;
            std.mem.doNotOptimizeAway(&pk_sink);
        }

        noinline fn callSign() void {
            sig_len = (if (is1024) falcon.signRandomized1024(&cur_sk, msg, rng_state.random(), &nonce_sink, &sig_sink) else falcon.signRandomized(&cur_sk, msg, rng_state.random(), &nonce_sink, &sig_sink)) catch unreachable;
            std.mem.doNotOptimizeAway(&sig_sink);
        }

        // ── needles ──

        fn seedFor(tag: u8) [48]u8 {
            var out: [48]u8 = undefined;
            var sh = Shake256.init(.{});
            sh.update("falcon-stackprobe-seed");
            sh.update(&[_]u8{ tag, @intFromBool(is1024) });
            sh.squeeze(&out);
            return out;
        }

        fn fftImage(name: []const u8, src: *const [n]i8, negate: bool) void {
            var a: [n]f64 = undefined;
            for (&a, src) |*d, s| d.* = fpr.of(s);
            fft.fftRaw(&a, logn);
            if (negate) fft.polyNeg(&a, logn);
            needles.addStride(name, std.mem.sliceAsBytes(&a), 8);
        }

        fn polyImages(src_name: []const u8, ntt_name: []const u8, src: *const [n]i8) void {
            var p: Ring.Poly = undefined;
            Ring.fromSmall(&p, src);
            needles.addImage(src_name, std.mem.sliceAsBytes(&p));
            Ring.ntt(&p);
            needles.addImage(ntt_name, std.mem.sliceAsBytes(&p));
        }

        /// Every in-memory form of the key the module itself can produce.
        fn keyNeedles(k: *const SigningKey) void {
            var bytes: [sk_len]u8 = undefined;
            k.toSecretKeyBytes(&bytes);
            needles.addImage("sk bytes", &bytes);
            needles.addImage("f", std.mem.sliceAsBytes(&k.f));
            needles.addImage("g", std.mem.sliceAsBytes(&k.g));
            needles.addImage("F", std.mem.sliceAsBytes(&k.big_f));
            needles.addImage("G", std.mem.sliceAsBytes(&k.big_g));
            polyImages("f (poly)", "f (ntt)", &k.f);
            polyImages("g (poly)", "g (ntt)", &k.g);
            fftImage("f (fft)", &k.f, false);
            fftImage("-f (fft)", &k.f, true);
            fftImage("g (fft)", &k.g, false);
            fftImage("F (fft)", &k.big_f, false);
            fftImage("-F (fft)", &k.big_f, true);
            fftImage("G (fft)", &k.big_g, false);
        }

        fn rngNeedles(seed: *const [48]u8) void {
            needles.addImage("seed", seed);
            var r: sign.ShakePrng = undefined;
            r.init(seed);
            var stream: [2048]u8 = undefined;
            r.random().bytes(&stream);
            needles.addImage("rng stream", &stream);
        }

        /// The sampler's Gram matrix (reference `do_sign_dyn`, as in
        /// `ffsampling.sampleSignature`).
        fn gramNeedles(k: *const SigningKey) void {
            var b00: [n]f64 = undefined;
            var b01: [n]f64 = undefined;
            var b10: [n]f64 = undefined;
            var b11: [n]f64 = undefined;
            var t0: [n]f64 = undefined;
            var t1: [n]f64 = undefined;
            for (&b01, k.f) |*d, s| d.* = fpr.of(s);
            for (&b00, k.g) |*d, s| d.* = fpr.of(s);
            for (&b11, k.big_f) |*d, s| d.* = fpr.of(s);
            for (&b10, k.big_g) |*d, s| d.* = fpr.of(s);
            fft.fftRaw(&b01, logn);
            fft.fftRaw(&b00, logn);
            fft.fftRaw(&b11, logn);
            fft.fftRaw(&b10, logn);
            fft.polyNeg(&b01, logn);
            fft.polyNeg(&b11, logn);
            @memcpy(&t0, &b01);
            fft.polyMulselfadjFft(&t0, logn);
            @memcpy(&t1, &b00);
            fft.polyMulAdjFft(&t1, &b10, logn);
            fft.polyMulselfadjFft(&b00, logn);
            fft.polyAdd(&b00, &t0, logn);
            fft.polyMulAdjFft(&b01, &b11, logn);
            fft.polyAdd(&b01, &t1, logn);
            fft.polyMulselfadjFft(&b10, logn);
            @memcpy(&t1, &b11);
            fft.polyMulselfadjFft(&t1, logn);
            fft.polyAdd(&b10, &t1, logn);
            needles.addStride("gram g00", std.mem.sliceAsBytes(&b00), 8);
            needles.addStride("gram g01", std.mem.sliceAsBytes(&b01), 8);
            needles.addStride("gram g11", std.mem.sliceAsBytes(&b10), 8);
        }

        /// The first attempt's randomness and the accepted candidate. Fails
        /// (so the seed gets changed) if the first attempt was rejected.
        fn signNeedles(rng_seed: *const [48]u8, sig: []const u8) !void {
            var r: sign.ShakePrng = undefined;
            r.init(rng_seed);
            var nonce: [falcon.nonce_length]u8 = undefined;
            r.random().bytes(&nonce);
            try std.testing.expectEqualSlices(u8, &nonce, &nonce_sink); // attempt 0 accepted
            var seed48: [48]u8 = undefined;
            r.random().bytes(&seed48);
            needles.addImage("seed48", &seed48);
            var sh = Shake256.init(.{});
            sh.update(&seed48);
            var pseed: [56]u8 = undefined;
            sh.squeeze(&pseed);
            needles.addImage("pseed", &pseed);
            const prng = gaussian.Prng.init(&pseed);
            needles.addImage("chacha", std.mem.asBytes(&prng));

            var s2: [n]i16 = undefined;
            try Codec.compDecode(&s2, sig[1..]);
            needles.addImage("s2", std.mem.sliceAsBytes(&s2));
            var c: Ring.Poly = undefined;
            Codec.hashToPoint(&nonce, msg, &c);
            var h = pk_sink.h_ntt;
            _ = &h;
            var tt: Ring.Poly = undefined;
            for (&tt, s2) |*x, v| {
                const w: i32 = v;
                x.* = @intCast(if (w < 0) w + @as(i32, poly.q) else w);
            }
            Ring.ntt(&tt);
            Ring.pointwiseMul(&tt, &h);
            Ring.intt(&tt);
            var s1: [n]i16 = undefined;
            for (&s1, tt, c) |*d, hs2, cc| {
                var w: i32 = @as(i32, cc) - @as(i32, hs2);
                w = @mod(w, @as(i32, poly.q));
                if (w > poly.q / 2) w -= poly.q;
                d.* = @intCast(w);
            }
            needles.addImage("s1", std.mem.sliceAsBytes(&s1));
        }

        // ── the probes ──

        fn run(label: []const u8, call: *const fn () void) !usize {
            needles.sort();
            return runProbe(label, call, &needles);
        }

        fn all() !usize {
            const tag = if (is1024) "-1024" else "-512";
            var bad: usize = 0;
            pre_fn = &reseed;
            defer pre_fn = null;

            // keygen
            cur_seed = seedFor(1);
            leak_src = cur_seed[0..LEAK].*;
            reseed();
            callKeygen();
            cur_sk = sk_sink; // the key this seed produces
            {
                needles.reset();
                rngNeedles(&cur_seed);
                keyNeedles(&cur_sk);
                bad += try run("generateKeyPair" ++ tag, callKeygen);
            }

            // encode / decode / publicKey
            leak_src = @bitCast(cur_sk.big_f[0..LEAK].*);
            cur_sk.toSecretKeyBytes(&cur_bytes);
            pre_fn = null;
            {
                needles.reset();
                keyNeedles(&cur_sk);
                bad += try run("toSecretKeyBytes" ++ tag, callEncode);
            }
            {
                needles.reset();
                keyNeedles(&cur_sk);
                bad += try run("SecretKey.fromBytes" ++ tag, callDecode);
            }
            callDecode();
            {
                needles.reset();
                keyNeedles(&cur_sk);
                bad += try run("SecretKey.publicKey" ++ tag, callPublicKey);
            }

            // sign (rng reseeded for every repetition, so the stream replays)
            const rng_seed = seedFor(2);
            cur_seed = rng_seed;
            pre_fn = &reseed;
            reseed();
            callSign();
            {
                needles.reset();
                keyNeedles(&cur_sk);
                gramNeedles(&cur_sk);
                try signNeedles(&rng_seed, sig_sink[0..sig_len]);
                bad += try run("signRandomized" ++ tag, callSign);
            }
            return bad;
        }
    };
}

test "STACKPROBE: falcon-512 keygen, secret-key decode/encode and signing leave no secret on the dead stack" {
    try skipUnlessOptimized();
    try std.testing.expectEqual(@as(usize, 0), try Suite(false).all());
}

test "STACKPROBE: falcon-1024 keygen, secret-key decode/encode and signing leave no secret on the dead stack" {
    try skipUnlessOptimized();
    try std.testing.expectEqual(@as(usize, 0), try Suite(true).all());
}
