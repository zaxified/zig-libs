// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for SLH-DSA key generation and signing
//! (`keyGen`, `keyGenFromSeed`, `sign`, `signInternal`), over SHA2 and SHAKE
//! parameter sets, small (`s`) and fast (`f`) variants. Kept in the module
//! per `CONVENTIONS.md` §9.
//!
//! Method as `ssh`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in:
//! - `SK.seed` and `SK.prf`;
//! - for the SHA2 sets the HMAC key images of PRF_msg: `SK.prf ⊕ 0x36` and
//!   `SK.prf ⊕ 0x5c` (the padded key blocks) and the hash states after
//!   absorbing them;
//! - the WOTS+ chain-start secrets `F(PK.seed, ADRS, SK.seed)` (chains 0 and
//!   1) of every leaf of the top-layer tree (address tree 0, which key
//!   generation and every signature compute). The FORS leaf secrets live at
//!   a message-dependent address and are not recomputed here: they come out of
//!   the same `F(.., SK.seed)` step, so the `SK.seed` windows cover the input
//!   they would be derived from.
//! Windows with fewer than 8 distinct bytes are skipped.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const engine = @import("engine.zig");
const params = @import("params.zig");
const address = @import("address.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Shake256 = std.crypto.hash.sha3.Shake256;

const WINDOW = 1024 * 1024;
const LEAK = 16;
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
        std.debug.print("\n=== STACKPROBE slhdsa: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<16} {d} (5 calls)\n", .{ name, total[i] });
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

// ── per-parameter-set harness ───────────────────────────────────────────────

fn Harness(comptime P: params.Params) type {
    return struct {
        const S = engine.SlhDsa(P);
        const n = S.n;

        // The caller's own storage — a signer holds its key in a static or a
        // long-lived struct like these.
        var seed_src: [3 * n]u8 = undefined;
        var key: S.KeyPair = undefined;
        var kp_sink: S.KeyPair = undefined;
        var sig_sink: [S.signature_length]u8 = undefined;
        const msg = "slhdsa stack probe message";
        const addrnd: [n]u8 = @splat(0x5c);

        noinline fn callKeyGen() void {
            S.keyGen(&kp_sink, &seed_src);
            std.mem.doNotOptimizeAway(&kp_sink);
        }

        noinline fn callKeyGenFromSeed() void {
            S.keyGenFromSeed(&kp_sink, seed_src[0..n], seed_src[n .. 2 * n], seed_src[2 * n ..][0..n]);
            std.mem.doNotOptimizeAway(&kp_sink);
        }

        noinline fn callSign() void {
            S.sign(&sig_sink, msg, &key.sk, "ctx", null) catch unreachable;
            std.mem.doNotOptimizeAway(&sig_sink);
        }

        noinline fn callSignInternal() void {
            S.signInternal(&sig_sink, msg, &key.sk, addrnd);
            std.mem.doNotOptimizeAway(&sig_sink);
        }

        var sk_sink: S.SecretKey = undefined;
        var sk_bytes: [S.secret_key_length]u8 = undefined;

        noinline fn callFromBytes() void {
            S.SecretKey.fromBytes(&sk_sink, &sk_bytes);
            std.mem.doNotOptimizeAway(&sk_sink);
        }

        noinline fn callToBytes() void {
            key.sk.toBytes(&sk_bytes);
            std.mem.doNotOptimizeAway(&sk_bytes);
        }

        /// F(PK.seed, ADRS, sk_seed): the PRF the secret values come from.
        fn prf(pk_seed: *const [n]u8, adrs: address.Address, sk_seed: *const [n]u8) [n]u8 {
            if (comptime P.hash == .shake) {
                var st = Shake256.init(.{});
                st.update(pk_seed);
                st.update(&adrs.bytes);
                st.update(sk_seed);
                var out: [n]u8 = undefined;
                st.squeeze(&out);
                return out;
            }
            var st = Sha256.init(.{});
            st.update(pk_seed);
            st.update(&(@as([64 - n]u8, @splat(0))));
            st.update(&adrs.compressed());
            st.update(sk_seed);
            var digest: [32]u8 = undefined;
            st.final(&digest);
            return digest[0..n].*;
        }

        fn seedNeedles(nd: *Needles) void {
            nd.addImage("SK.seed", key.sk.seed[0..]);
            nd.addImage("SK.prf", key.sk.prf[0..]);
        }

        /// WOTS+ chain-start secrets of the top layer's tree 0, every leaf.
        fn wotsNeedles(nd: *Needles) void {
            for (0..1 << P.hp) |leaf| {
                for (0..2) |chain| {
                    var a: address.Address = .{};
                    a.setLayer(P.d - 1);
                    a.setTypeAndClear(.wots_prf);
                    a.setKeyPair(@intCast(leaf));
                    a.setChain(@intCast(chain));
                    const sk = prf(&key.pk.seed, a, &key.sk.seed);
                    nd.addImage("WOTS+ sk", &sk);
                }
            }
        }

        /// The HMAC key blocks of PRF_msg (SHA2 sets) and the hash states
        /// after absorbing them.
        fn hmacNeedles(nd: *Needles) void {
            if (comptime P.hash != .sha2) return;
            const H = if (n == 16) Sha256 else Sha512;
            inline for (.{ .{ 0x36, "HMAC ipad" }, .{ 0x5c, "HMAC opad" } }) |c| {
                var block: [H.block_length]u8 = @splat(c[0]);
                for (key.sk.prf, 0..) |b, i| block[i] = b ^ c[0];
                nd.addImage(c[1], block[0..n]);
                var st = H.init(.{});
                st.update(&block);
                nd.addImage(c[1] ++ " state", std.mem.asBytes(&st.s));
            }
        }

        /// The needle formula must be the engine's: a top-layer WOTS+ signature
        /// element whose digit is 0 IS the chain-start secret, so at least one
        /// recomputed secret has to appear in the signature the engine made.
        fn checkWotsFormula() !void {
            callSign();
            const xmss_sig_len = (P.wotsLen() + P.hp) * n;
            const fors_sig_len = P.k * (1 + P.a) * n;
            const last = S.signature_length - xmss_sig_len;
            std.debug.assert(last == n + fors_sig_len + (P.d - 1) * xmss_sig_len);
            var found: usize = 0;
            for (0..1 << P.hp) |leaf| {
                for (0..P.wotsLen()) |chain| {
                    var a: address.Address = .{};
                    a.setLayer(P.d - 1);
                    a.setTypeAndClear(.wots_prf);
                    a.setKeyPair(@intCast(leaf));
                    a.setChain(@intCast(chain));
                    const sk = prf(&key.pk.seed, a, &key.sk.seed);
                    if (std.mem.eql(u8, &sk, sig_sink[last + chain * n ..][0..n])) found += 1;
                }
            }
            try std.testing.expect(found >= 1);
        }

        fn run(comptime label: []const u8) !usize {
            var bad: usize = 0;
            // High-entropy bytes (a repeated byte would be skipped).
            var h = Sha512.init(.{});
            h.update(label);
            var wide: [64]u8 = undefined;
            h.final(&wide);
            for (&seed_src, 0..) |*b, i| b.* = wide[i % 64] ^ @as(u8, @truncate(i * 29));
            leak_src = seed_src[0..LEAK].*;

            // Reference key (computed through the same engine entry point).
            callKeyGen();
            key = kp_sink;
            try checkWotsFormula();

            {
                var nd: Needles = .{};
                seedNeedles(&nd);
                wotsNeedles(&nd);
                nd.sort();
                bad += try runProbe(label ++ " keyGen", callKeyGen, &nd);
                bad += try runProbe(label ++ " keyGenFromSeed", callKeyGenFromSeed, &nd);
            }
            {
                var nd: Needles = .{};
                seedNeedles(&nd);
                hmacNeedles(&nd);
                wotsNeedles(&nd);
                nd.sort();
                bad += try runProbe(label ++ " sign", callSign, &nd);
                bad += try runProbe(label ++ " signInternal (hedged)", callSignInternal, &nd);
            }
            {
                var nd: Needles = .{};
                seedNeedles(&nd);
                nd.sort();
                key.sk.toBytes(&sk_bytes);
                bad += try runProbe(label ++ " SecretKey.fromBytes", callFromBytes, &nd);
                bad += try runProbe(label ++ " SecretKey.toBytes", callToBytes, &nd);
            }
            return bad;
        }
    };
}

test "STACKPROBE: no SK.seed, SK.prf or WOTS+ secret on the dead stack after SLH-DSA key generation and signing" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    bad += try Harness(params.sha2_128f).run("sha2-128f");
    bad += try Harness(params.sha2_128s).run("sha2-128s");
    bad += try Harness(params.shake_128f).run("shake-128f");
    bad += try Harness(params.sha2_192f).run("sha2-192f");
    bad += try Harness(params.shake_256s).run("shake-256s");
    bad += try Harness(params.shake_256f).run("shake-256f");
    bad += try Harness(params.sha2_256f).run("sha2-256f");
    try std.testing.expectEqual(@as(usize, 0), bad);
}
