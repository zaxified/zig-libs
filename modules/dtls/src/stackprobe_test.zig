// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for CertificateVerify signing
//! (`certverify.sign`, all four key families: RSA-PSS, ECDSA P-256, ECDSA
//! P-384, Ed25519) and, in the second test (bottom of the file), for the key
//! exchange, key schedule and record keys of a full in-memory handshake.
//! Kept in the module per `CONVENTIONS.md` §9.
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
    names: [48][]const u8 = undefined,
    n_names: usize = 0,

    fn addImage(self: *Needles, name: []const u8, image: []const u8) void {
        const id: u8 = @intCast(self.lookupName(name));
        var i: usize = 0;
        while (i + W <= image.len) : (i += 1) {
            if (self.len >= max_windows) @panic("needle set overflow");
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

const Hits = [48]usize;

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

/// Runs before every measured call, outside the painted window (default: none).
/// The handshake probe restores the `Connection` the call starts from.
fn noPrep() void {}
var prep_fn: *const fn () void = &noPrep;

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
    prep_fn(); // restore the state the call starts from (before the paint)
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
    prep_fn();
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

// ═════════════════════════════════════════════════════════════════════════════
// Key exchange and key schedule: a full in-memory client <-> server handshake
// ═════════════════════════════════════════════════════════════════════════════
//
// The measured call is ONE public step of the handshake (`startHandshake`,
// `handleFlight` on either side, `send`, `recv`) on a `Connection` that lives in
// static memory. A reference run walks the whole handshake once and keeps, for
// every step, the connection as it was BEFORE the step (`pre`), the datagram
// fed to it and every byte the (recording) entropy source handed out. Each
// measured call restores `pre` and re-seeds the entropy first (`prepStep`, run
// before the window is painted), so the five repetitions of a probe see the
// same secrets. Needles are derived from that reference run:
//   - every entropy draw that is not on the wire (the ECDHE scalars and ML-KEM
//     seeds, the encapsulation seed, the signing noise) and its clamped /
//     expanded images (X25519 scalar, ML-KEM decapsulation key);
//   - the client's ECDHE secret as it sits in the live connection, the shared
//     secret recomputed from it and the server's share;
//   - early / derived / handshake / master secrets recomputed from that
//     shared secret; the traffic secrets, the finished keys and every record
//     key, IV, sequence-number key (and AES round keys / GHASH key) read from the
//     live connections;
//   - the PSK (PSK sets) and the certificate signing keys.

const dtls = @import("root.zig");
const Connection = dtls.Connection;
const cert_kat = @import("certauth_kat_vectors.zig");
const keyschedule = @import("keyschedule.zig");
const MlKem768 = std.crypto.kem.ml_kem.MLKem768;
const X25519 = std.crypto.dh.X25519;
const P256c = std.crypto.ecc.P256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128 = std.crypto.core.aes.Aes128;
const NamedGroup = dtls.messages.NamedGroup;

const Step = enum(u8) { c_start, s_hello, c_flight2, s_fin, c_send, s_recv, s_send, c_recv, c_install };
const n_steps = 9;

fn isClient(st: Step) bool {
    return switch (st) {
        .c_start, .c_flight2, .c_send, .c_recv, .c_install => true,
        .s_hello, .s_fin, .s_recv, .s_send => false,
    };
}

/// Entropy source that records every `fill` it serves (one entry per call).
const Rec = struct {
    prng: std.Random.DefaultPrng = undefined,
    log: [4096]u8 = undefined,
    n: usize = 0,
    ent_off: [64]u16 = undefined,
    ent_len: [64]u16 = undefined,
    n_ent: usize = 0,

    fn reset(self: *Rec, seed: u64) void {
        self.prng = .init(seed);
        self.n = 0;
        self.n_ent = 0;
    }

    fn fill(self: *Rec, buf: []u8) void {
        self.prng.random().bytes(buf);
        if (self.n_ent < 64 and self.n + buf.len <= self.log.len) {
            self.ent_off[self.n_ent] = @intCast(self.n);
            self.ent_len[self.n_ent] = @intCast(buf.len);
            self.n_ent += 1;
            @memcpy(self.log[self.n..][0..buf.len], buf);
            self.n += buf.len;
        }
    }

    fn random(self: *Rec) std.Random {
        return std.Random.init(self, fill);
    }
};

// The connections, their pre-step snapshots and every buffer live in static
// memory, so none of them is part of the probed stack window.
var live_client: Connection = undefined;
var live_server: Connection = undefined;
var pre: [n_steps]Connection = undefined;
var in_store: [n_steps][6144]u8 = undefined;
var in_len: [n_steps]usize = @splat(0);
var out_buf: [6144]u8 = undefined;
var plain_buf: [256]u8 = undefined;
var out_len: usize = 0;
var step_failed = false;
var cur_step: Step = .c_start;
var cur_seed: u64 = 0;
var rec: Rec = .{};
var step_rec: [n_steps]Rec = undefined;
var needles_store: Needles = .{};

/// Secrets for the `installApplicationKeys` step (the server's pending ones).
var inst_c: [32]u8 = undefined;
var inst_s: [32]u8 = undefined;

const app_msg = "dtls kex probe application record";

fn connOf(st: Step) *Connection {
    return if (isClient(st)) &live_client else &live_server;
}

fn stepIn(st: Step) []const u8 {
    return in_store[@intFromEnum(st)][0..in_len[@intFromEnum(st)]];
}

fn setIn(st: Step) void {
    @memcpy(in_store[@intFromEnum(st)][0..out_len], out_buf[0..out_len]);
    in_len[@intFromEnum(st)] = out_len;
}

/// API adapter: the one place that names how a step calls the module.
fn doStep(st: Step) void {
    const ent: dtls.Entropy = .{ .seeded_for_test = rec.random() };
    switch (st) {
        .c_start => {
            const o = live_client.startHandshake(ent, 0, &out_buf) catch return failStep();
            out_len = o.len;
        },
        .s_hello, .s_fin => {
            const r = live_server.handleFlight(stepIn(st), ent, 0, &out_buf) catch return failStep();
            out_len = r.out.len;
        },
        .c_flight2 => {
            const r = live_client.handleFlight(stepIn(st), ent, 0, &out_buf) catch return failStep();
            out_len = r.out.len;
        },
        .c_send => {
            const o = live_client.send(app_msg, &out_buf) catch return failStep();
            out_len = o.len;
        },
        .s_recv => {
            const o = live_server.recv(stepIn(st), &plain_buf) catch return failStep();
            out_len = o.len;
        },
        .s_send => {
            const o = live_server.send(app_msg, &out_buf) catch return failStep();
            out_len = o.len;
        },
        .c_recv => {
            const o = live_client.recv(stepIn(st), &plain_buf) catch return failStep();
            out_len = o.len;
        },
        .c_install => {
            live_client.installApplicationKeys(live_client.suite, &inst_c, &inst_s) catch return failStep();
            out_len = 0;
        },
    }
}

fn failStep() void {
    step_failed = true;
}

noinline fn callStep() void {
    doStep(cur_step);
}

fn prepStep() void {
    @memcpy(std.mem.asBytes(connOf(cur_step)), std.mem.asBytes(&pre[@intFromEnum(cur_step)]));
    rec.reset(cur_seed +% @intFromEnum(cur_step));
}

/// Walk the handshake once; fill `pre`, the inputs and `step_rec`.
fn reference(cfg_c: dtls.Config, cfg_s: dtls.Config) !void {
    live_client = try Connection.clientInit(cfg_c);
    live_server = try Connection.serverInit(cfg_s);
    in_len = @splat(0);
    for (0..n_steps) |i| {
        const st: Step = @enumFromInt(i);
        cur_step = st;
        @memcpy(std.mem.asBytes(&pre[i]), std.mem.asBytes(connOf(st)));
        prepStep();
        step_failed = false;
        if (st == .c_install) {
            inst_c = pre[@intFromEnum(Step.s_fin)].pending_ap_client;
            inst_s = pre[@intFromEnum(Step.s_fin)].pending_ap_server;
        }
        doStep(st);
        try std.testing.expect(!step_failed);
        step_rec[i] = rec;
        switch (st) {
            .c_start => setIn(.s_hello),
            .s_hello => setIn(.c_flight2),
            .c_flight2 => setIn(.s_fin),
            .c_send => setIn(.s_recv),
            .s_send => setIn(.c_recv),
            .s_fin, .s_recv, .c_recv, .c_install => {},
        }
    }
    try std.testing.expectEqual(dtls.connection.State.connected, live_client.state);
    try std.testing.expectEqual(dtls.connection.State.connected, live_server.state);
}

fn onWire(chunk: []const u8) bool {
    for ([_]Step{ .s_hello, .c_flight2, .s_fin }) |st| {
        if (std.mem.indexOf(u8, stepIn(st), chunk) != null) return true;
    }
    return false;
}

fn addDir(n: *Needles, d: anytype, aes: bool) void {
    n.addBig("record key", d.key[0..d.key_len]);
    n.addBig("sn key", d.sn_key[0..d.sn_len]);
    if (aes) {
        addAes(n, d.key[0..16].*);
        addAes(n, d.sn_key[0..16].*);
    }
}

fn addAes(n: *Needles, key: [16]u8) void {
    const aes = Aes128.initEnc(key);
    n.addImage("aes round keys", std.mem.asBytes(&aes));
    var h: [16]u8 = undefined;
    aes.encrypt(&h, &@as([16]u8, @splat(0)));
    n.addBig("ghash H", &h);
}

const Set = struct {
    name: []const u8,
    psk: bool,
    group: NamedGroup,
    suite: dtls.CipherSuite,
    mutual: bool = false,
};

const sets = [_]Set{
    .{ .name = "psk aes128gcm", .psk = true, .group = .x25519, .suite = .aes_128_gcm_sha256 },
    .{ .name = "psk chacha20", .psk = true, .group = .x25519, .suite = .chacha20_poly1305_sha256 },
    .{ .name = "cert x25519 aes128gcm", .psk = false, .group = .x25519, .suite = .aes_128_gcm_sha256 },
    .{ .name = "cert p256 chacha20 mutual", .psk = false, .group = .secp256r1, .suite = .chacha20_poly1305_sha256, .mutual = true },
    .{ .name = "cert x25519mlkem768 aes128gcm", .psk = false, .group = .x25519_ml_kem768, .suite = .aes_128_gcm_sha256 },
};

var psk_store: [32]u8 = undefined;
var sk_server: Ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var sk_client: Ecdsa.EcdsaP256Sha256.SecretKey = undefined;

fn configs(comptime set: Set) !struct { c: dtls.Config, s: dtls.Config } {
    const suites = [_]dtls.CipherSuite{set.suite};
    if (set.psk) {
        return .{
            .c = .{ .role = .client, .psk_identity = "device-042", .psk = &psk_store, .cipher_suites = &suites },
            .s = .{ .role = .server, .psk_identity = "device-042", .psk = &psk_store, .cipher_suites = &suites },
        };
    }
    sk_server = try Ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes);
    sk_client = try Ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.client_secret_key_bytes);
    var c: dtls.Config = .{
        .role = .client,
        .key_exchange = .cert_dhe,
        .key_share_group = set.group,
        .cipher_suites = &suites,
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = cert_kat.valid_now_sec,
        .require_peer_cert = true,
    };
    var s: dtls.Config = .{
        .role = .server,
        .key_exchange = .cert_dhe,
        .cipher_suites = &suites,
        .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = .{ .ecdsa_p256 = &sk_server } },
    };
    if (set.mutual) {
        c.cert = .{ .chain = &.{&cert_kat.client_cert_der}, .private_key = .{ .ecdsa_p256 = &sk_client } };
        s.request_client_cert = true;
        s.require_peer_cert = true;
        s.peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der };
        s.now_sec = cert_kat.valid_now_sec;
    }
    return .{ .c = c, .s = s };
}

/// Needles from the reference run (see the section header). Returns the
/// 32-byte control secret.
fn buildNeedles(n: *Needles, comptime set: Set) ![LEAK]u8 {
    n.len = 0;
    n.n_names = 0;
    const aes = set.suite == .aes_128_gcm_sha256;

    // Entropy that is not on the wire.
    for (0..n_steps) |i| {
        const r = &step_rec[i];
        for (0..r.n_ent) |e| {
            const chunk = r.log[r.ent_off[e]..][0..r.ent_len[e]];
            if (onWire(chunk)) continue;
            n.addBig("entropy", chunk);
            if (chunk.len == 32) {
                var cl: [32]u8 = chunk[0..32].*;
                cl[0] &= 248;
                cl[31] &= 127;
                cl[31] |= 64;
                n.addBig("x25519 scalar", &cl);
            }
            if (chunk.len == MlKem768.seed_length) {
                const kp = try MlKem768.KeyPair.generateDeterministic(chunk[0..MlKem768.seed_length].*);
                n.addImage("ml-kem dk", std.mem.asBytes(&kp.secret_key));
                n.addImage("ml-kem dk", &kp.secret_key.toBytes());
            }
        }
    }

    var eh: [32]u8 = undefined;
    Sha256.hash("", &eh, .{});
    var dh: [64]u8 = undefined;
    var dh_len: usize = 0;
    var es: [32]u8 = undefined;
    if (set.psk) {
        n.addBig("psk", &psk_store);
        keyschedule.earlySecret(HkdfSha256, &es, &psk_store);
        var bk: [32]u8 = undefined;
        keyschedule.binderKey(HkdfSha256, &bk, &es, &eh);
        n.addBig("binder key", &bk);
        var bk_fin: [32]u8 = undefined;
        keyschedule.deriveFinishedKey(HkdfSha256, 32, &bk_fin, &bk);
        n.addBig("binder key", &bk_fin);
    } else {
        const cl = &pre[@intFromEnum(Step.c_flight2)];
        const sv = &pre[@intFromEnum(Step.s_fin)];
        const grp = cl.ecdhe_group;
        try std.testing.expectEqual(@intFromEnum(set.group), grp);
        const sec_len: usize = if (set.group == .x25519_ml_kem768) 96 else 32;
        n.addBig("ecdhe secret", cl.ecdhe_secret[0..sec_len]);
        const sp = sv.ecdhe_public[0..sv.ecdhe_public_len];
        switch (set.group) {
            .x25519 => {
                const ss = try X25519.scalarmult(cl.ecdhe_secret[0..32].*, sp[0..32].*);
                dh[0..32].* = ss;
                dh_len = 32;
            },
            .secp256r1 => {
                const point = try P256c.fromSec1(sp);
                const shared = try point.mul(cl.ecdhe_secret[0..32].*, .big);
                const a = shared.affineCoordinates();
                dh[0..32].* = a.x.toBytes(.big);
                dh_len = 32;
                n.addBig("dh y", &a.y.toBytes(.big));
                n.addImage("dh fe", std.mem.asBytes(&a.x));
                n.addImage("dh fe", std.mem.asBytes(&a.y));
            },
            .x25519_ml_kem768 => {
                const kp = try MlKem768.KeyPair.generateDeterministic(cl.ecdhe_secret[0..MlKem768.seed_length].*);
                const ss_pq = try kp.secret_key.decaps(sp[0..MlKem768.ciphertext_length]);
                const ss_x = try X25519.scalarmult(cl.ecdhe_secret[MlKem768.seed_length..][0..32].*, sp[MlKem768.ciphertext_length..][0..32].*);
                dh[0..32].* = ss_pq;
                dh[32..64].* = ss_x;
                dh_len = 64;
                n.addBig("ss_pq", &ss_pq);
                n.addBig("ss_x", &ss_x);
            },
            else => unreachable,
        }
        n.addBig("dh shared", dh[0..dh_len]);
        const zero_psk: [32]u8 = @splat(0);
        keyschedule.earlySecret(HkdfSha256, &es, &zero_psk);
        n.addBig("server sign key", &cert_kat.server_secret_key_bytes);
        if (set.mutual) n.addBig("client sign key", &cert_kat.client_secret_key_bytes);
    }
    n.addBig("early secret", &es);
    var derived: [32]u8 = undefined;
    keyschedule.deriveSecret(HkdfSha256, &derived, &es, "derived", &eh);
    n.addBig("derived", &derived);
    var hs: [32]u8 = undefined;
    var ms: [32]u8 = undefined;
    keyschedule.deriveHandshakeSecret(HkdfSha256, &hs, &es, &eh, if (set.psk) null else dh[0..dh_len]);
    keyschedule.deriveMasterSecret(HkdfSha256, &ms, &hs, &eh);
    n.addBig("handshake secret", &hs);
    keyschedule.deriveSecret(HkdfSha256, &derived, &hs, "derived", &eh);
    n.addBig("derived", &derived);
    n.addBig("master secret", &ms);

    // Traffic secrets from the live server, after ServerHello..Finished.
    const sv = &pre[@intFromEnum(Step.s_fin)];
    n.addBig("hs traffic c", &sv.hs_traffic_client);
    n.addBig("hs traffic s", &sv.hs_traffic_server);
    n.addBig("ap traffic c", &sv.pending_ap_client);
    n.addBig("ap traffic s", &sv.pending_ap_server);
    var fkey: [32]u8 = undefined;
    keyschedule.deriveFinishedKey(HkdfSha256, 32, &fkey, &sv.hs_traffic_client);
    n.addBig("finished key", &fkey);
    keyschedule.deriveFinishedKey(HkdfSha256, 32, &fkey, &sv.hs_traffic_server);
    n.addBig("finished key", &fkey);
    // The schedule is only a needle if it is the engine's: it must reproduce the
    // application secrets the server derived from it.
    const th = sv.transcript.currentHash();
    var ap_c: [32]u8 = undefined;
    var ap_s: [32]u8 = undefined;
    keyschedule.deriveApplicationTrafficSecrets(HkdfSha256, &ap_c, &ap_s, &ms, &th);
    try std.testing.expectEqualSlices(u8, &sv.pending_ap_client, &ap_c);
    try std.testing.expectEqualSlices(u8, &sv.pending_ap_server, &ap_s);

    addDir(n, sv.hs_write_keys, aes);
    addDir(n, sv.hs_read_keys, aes);
    addDir(n, live_client.write_keys, aes);
    addDir(n, live_client.read_keys, aes);
    addDir(n, live_server.write_keys, aes);
    addDir(n, live_server.read_keys, aes);

    var ctl: [LEAK]u8 = undefined;
    Sha256.hash(set.name, &ctl, .{});
    n.addBig("control", &ctl);
    n.sort();
    return ctl;
}

test "STACKPROBE: no ECDHE, key-schedule or record-key residue on the dead stack after a full handshake" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    inline for (sets, 0..) |set, si| {
        Sha256.hash(set.name, &psk_store, .{});
        cur_seed = 0xD715_0000 + si * 64;
        const cfg = try configs(set);
        try reference(cfg.c, cfg.s);
        leak_src = try buildNeedles(&needles_store, set);
        prep_fn = prepStep;
        inline for (comptime std.meta.tags(Step)) |st| {
            cur_step = st;
            bad += try runProbe("kex " ++ set.name ++ " " ++ @tagName(st), callStep, &needles_store);
        }
        prep_fn = noPrep;
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
