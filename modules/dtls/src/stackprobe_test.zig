// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for CertificateVerify signing
//! (`certverify.sign`, all four key families: RSA-PSS, ECDSA P-256, ECDSA
//! P-384, Ed25519). Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets. The key
//! is held in a `var` (as a connection's `CertConfig` holds it) and the PUBLIC
//! entry point is measured. ReleaseFast / ReleaseSmall only — Debug and
//! ReleaseSafe fill `undefined` with 0xaa, so the scan cannot see a dead frame
//! there.
//!
//! Needles are every 16-byte window of every image a secret is held in:
//!   - ECDSA: the private key `d`, the nonce `k` (solved from the signature
//!     the call produced, `k = s⁻¹·(e + r·d)`, so whatever nonce std really
//!     used), `k⁻¹`, `r·d` and `e + r·d` (`e` = the hash of exactly the
//!     signed content);
//!   - Ed25519: the seed, `SHA-512(seed)`, the clamped scalar `a`, the 32-byte
//!     prefix and the nonce `r = SHA-512(prefix ‖ M) mod L`;
//!   - RSA: p, q, d, dP, dQ, qInv (big/little endian and their `ff` /
//!     `montint` images in the key struct) and the CRT halves `s mod p`,
//!     `s mod q` of the produced signature.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const rsa = @import("rsa");
const certverify = @import("certverify.zig");
const kat = @import("certverify_kat_vectors.zig");

const Ecdsa = std.crypto.sign.ecdsa;
const Ed25519 = std.crypto.sign.Ed25519;
const P256 = std.crypto.ecc.P256;
const P384 = std.crypto.ecc.P384;
const Edwards = std.crypto.ecc.Edwards25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;

const WINDOW = 256 * 1024;
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

    /// Both byte orders of a big-endian value.
    fn addBig(self: *Needles, name: []const u8, be: []const u8) void {
        self.addImage(name, be);
        var buf: [512]u8 = undefined;
        const r = buf[0..be.len];
        @memcpy(r, be);
        std.mem.reverse(u8, r);
        self.addImage(name, r);
    }

    fn addScalar(self: *Needles, name: []const u8, s: anytype) void {
        const be = s.toBytes(.big);
        self.addBig(name, &be);
        self.addImage(name, std.mem.asBytes(&s));
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
// own header and locals hid the top few hundred bytes (2026-10-08).
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
        std.debug.print("\n=== STACKPROBE dtls: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

// ── keys and the probed calls (all `noinline`, secrets read from static memory) ──

// Key storage with an address, as a connection's owner would have it.
var key_rsa: rsa.SecretKey = undefined;
var key_p256: Ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var key_p384: Ecdsa.EcdsaP384Sha384.SecretKey = undefined;
var key_ed: Ed25519.SecretKey = undefined;
/// The key a caller holds: a `var`, as `Connection.CertConfig` holds it.
var cur_key: certverify.SecretKey = undefined;

const th256: [32]u8 = @splat(0x11);
const th384: [48]u8 = @splat(0x22);
const th512: [64]u8 = @splat(0x33);
const scheme_ed = certverify.SignatureScheme.ed25519;

var cur_scheme: certverify.SignatureScheme = undefined;
var cur_th: []const u8 = &.{};
var cur_noise: std.Random.DefaultPrng = undefined;
var use_noise = false;
var sig_buf: [rsa.max_modulus_len]u8 = undefined;
var sig_len: usize = 0;

noinline fn callSign() void {
    var rnd: ?std.Random = null;
    if (use_noise) {
        cur_noise = .init(0x5eed);
        rnd = cur_noise.random();
    }
    const s = certverify.sign(cur_scheme, cur_key, .server, cur_th, rnd, &sig_buf) catch unreachable;
    sig_len = s.len;
    std.mem.doNotOptimizeAway(s.ptr);
}

/// The exact bytes `sign` signs.
fn signedContent(buf: *[certverify.max_signed_content_len]u8) ![]u8 {
    return certverify.buildSignedContent(.server, cur_th, buf);
}

fn caseSeed(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'd', 't', 'l', 's', '-', 's', 'e', 'e', 'd', i }, &out, .{});
    return out;
}

// ── needles ─────────────────────────────────────────────────────────────────

/// `d`, `k`, `k⁻¹`, `r·d`, `e + r·d` for an ECDSA signature `sig_der` over
/// `signed`, made with the big-endian private key `sk`.
fn ecdsaNeedles(comptime Curve: type, comptime Scheme: type, comptime Hash: type, n: *Needles, sk: *const [Curve.scalar.encoded_length]u8, signed: []const u8, sig_der: []const u8) !void {
    const Scalar = Curve.scalar.Scalar;
    var h: [Hash.digest_length]u8 = undefined;
    Hash.hash(signed, &h, .{});
    var wide: [64]u8 = @splat(0);
    @memcpy(wide[64 - h.len ..], &h);
    const e = Scalar.fromBytes64(wide, .big);
    const d = try Scalar.fromBytes(sk.*, .big);
    const sig = try Scheme.Signature.fromDer(sig_der);
    const raw = sig.toBytes();
    const L = Curve.scalar.encoded_length;
    const r = try Scalar.fromBytes(raw[0..L].*, .big);
    const s = try Scalar.fromBytes(raw[L..][0..L].*, .big);
    const rd = r.mul(d);
    const erd = e.add(rd);
    const k = s.invert().mul(erd);
    n.addScalar("d", d);
    n.addScalar("k", k);
    n.addScalar("k^-1", k.invert());
    n.addScalar("r*d", rd);
    n.addScalar("e+r*d", erd);
}

fn edNeedles(n: *Needles, seed: [32]u8, signed: []const u8) void {
    var az: [64]u8 = undefined;
    Sha512.hash(&seed, &az, .{});
    var a: [32]u8 = az[0..32].*;
    Edwards.scalar.clamp(&a);
    var h = Sha512.init(.{});
    h.update(az[32..64]);
    h.update(signed);
    var r64: [64]u8 = undefined;
    h.final(&r64);
    const r = Edwards.scalar.reduce64(r64);
    n.addImage("seed", &seed);
    n.addImage("sha512(seed)", &az);
    n.addImage("a (clamped)", &a);
    n.addImage("a mod L", &Edwards.scalar.reduce(a));
    n.addImage("prefix", az[32..64]);
    n.addImage("nonce r", &r);
    n.addImage("nonce r64", &r64);
}

fn feBytes(fe: rsa.Fe, comptime len: usize) [len]u8 {
    var out: [len]u8 = undefined;
    fe.toBytes(&out, .big) catch unreachable;
    return out;
}

fn pb32(sk: *const rsa.SecretKey) [LEAK]u8 {
    var pb: [128]u8 = undefined;
    sk.p.toBytes(&pb, .big) catch unreachable;
    return pb[0..LEAK].*;
}

fn rsaNeedles(n: *Needles, sk: *const rsa.SecretKey, sig: []const u8) void {
    var pb: [128]u8 = undefined;
    sk.p.toBytes(&pb, .big) catch unreachable;
    n.addBig("p", &pb);
    var qb: [128]u8 = undefined;
    sk.q.toBytes(&qb, .big) catch unreachable;
    n.addBig("q", &qb);
    n.addBig("d", &feBytes(sk.d, 256));
    n.addBig("dP", &feBytes(sk.dp, 128));
    n.addBig("dQ", &feBytes(sk.dq, 128));
    n.addBig("qInv", &feBytes(sk.qinv, 128));
    n.addImage("p (ff image)", std.mem.asBytes(&sk.p));
    n.addImage("q (ff image)", std.mem.asBytes(&sk.q));
    n.addImage("d (ff image)", std.mem.asBytes(&sk.d));
    n.addImage("dP (ff image)", std.mem.asBytes(&sk.dp));
    n.addImage("dQ (ff image)", std.mem.asBytes(&sk.dq));
    n.addImage("qInv (ff image)", std.mem.asBytes(&sk.qinv));
    n.addImage("p (montint)", std.mem.asBytes(&sk.p_mont));
    n.addImage("q (montint)", std.mem.asBytes(&sk.q_mont));
    // CRT halves of the produced signature (the two private-op results).
    const xi = std.mem.readInt(u2048, sig[0..256], .big);
    const pi: u2048 = std.mem.readInt(u1024, &pb, .big);
    const qi: u2048 = std.mem.readInt(u1024, &qb, .big);
    var b: [128]u8 = undefined;
    std.mem.writeInt(u1024, &b, @intCast(xi % pi), .big);
    n.addBig("s mod p", &b);
    std.mem.writeInt(u1024, &b, @intCast(xi % qi), .big);
    n.addBig("s mod q", &b);
}

// ── the tests ───────────────────────────────────────────────────────────────

const n_cases = 2;

test "STACKPROBE: no key, nonce or CRT residue on the dead stack after certverify.sign" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    var content_buf: [certverify.max_signed_content_len]u8 = undefined;

    for (0..n_cases) |ci| {
        const seed = caseSeed(@intCast(ci));

        // ECDSA P-256 (deterministic nonce, then with noise mixed in).
        {
            var sk_bytes: [32]u8 = seed;
            sk_bytes[0] &= 0x7f; // keep it below the group order
            leak_src = sk_bytes;
            key_p256 = try Ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(sk_bytes);
            setKey256();
            cur_scheme = .ecdsa_secp256r1_sha256;
            cur_th = &th256;
            for ([_]bool{ false, true }) |noise| {
                use_noise = noise;
                callSign();
                const signed = try signedContent(&content_buf);
                var n: Needles = .{};
                try ecdsaNeedles(P256, Ecdsa.EcdsaP256Sha256, Sha256, &n, &sk_bytes, signed, sig_buf[0..sig_len]);
                n.sort();
                bad += try runProbe(if (noise) "sign ecdsa_p256 (noise)" else "sign ecdsa_p256", callSign, &n);
            }
            use_noise = false;
        }

        // ECDSA P-384.
        {
            var sk_bytes: [48]u8 = undefined;
            Sha384.hash(&seed, &sk_bytes, .{});
            sk_bytes[0] &= 0x7f;
            leak_src = sk_bytes[0..32].*;
            key_p384 = try Ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(sk_bytes);
            setKey384();
            cur_scheme = .ecdsa_secp384r1_sha384;
            cur_th = &th384;
            callSign();
            const signed = try signedContent(&content_buf);
            var n: Needles = .{};
            try ecdsaNeedles(P384, Ecdsa.EcdsaP384Sha384, Sha384, &n, &sk_bytes, signed, sig_buf[0..sig_len]);
            n.sort();
            bad += try runProbe("sign ecdsa_p384", callSign, &n);
        }

        // Ed25519.
        {
            const kp = try Ed25519.KeyPair.generateDeterministic(seed);
            leak_src = seed;
            key_ed = kp.secret_key;
            setKeyEd();
            cur_scheme = scheme_ed;
            cur_th = &th256;
            callSign();
            const signed = try signedContent(&content_buf);
            var n: Needles = .{};
            edNeedles(&n, seed, signed);
            n.sort();
            bad += try runProbe("sign ed25519", callSign, &n);
        }

        // RSA-PSS: the KAT key, then a freshly generated one.
        for ([_]certverify.SignatureScheme{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha512 }, 0..) |scheme, si| {
            if (ci == 0) {
                try rsa.SecretKey.fromPrimes(&key_rsa, &kat.rsa_pss_sha256_server.p, &kat.rsa_pss_sha256_server.q, &kat.rsa_pss_sha256_server.e);
            } else {
                var prng = std.Random.DefaultPrng.init(0x7473 + si);
                var kp: rsa.KeyPair = undefined;
                try rsa.generate(&kp, prng.random(), 2048, 65537);
                key_rsa = kp.secret_key;
            }
            leak_src = pb32(&key_rsa);
            setKeyRsa();
            cur_scheme = scheme;
            cur_th = if (scheme == .rsa_pss_rsae_sha512) &th512 else &th256;
            use_noise = true; // the PSS salt: required, fixed seed per call
            callSign();
            var n: Needles = .{};
            rsaNeedles(&n, &key_rsa, sig_buf[0..sig_len]);
            n.sort();
            bad += try runProbe(if (si == 0) "sign rsa_pss_sha256" else "sign rsa_pss_sha512", callSign, &n);
            use_noise = false;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

// The only place the union is built.
fn setKey256() void {
    cur_key = .{ .ecdsa_p256 = &key_p256 };
}
fn setKey384() void {
    cur_key = .{ .ecdsa_p384 = &key_p384 };
}
fn setKeyEd() void {
    cur_key = .{ .ed25519 = &key_ed };
}
fn setKeyRsa() void {
    cur_key = .{ .rsa = &key_rsa };
}
