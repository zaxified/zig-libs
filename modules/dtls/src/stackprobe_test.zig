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
const certverify = @import("tls13").certverify;
const kat = @import("tls13").certverify_kat_vectors;

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
// own header and locals hid the top few hundred bytes.
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
/// (a negative-control "hit" of `x mod q` between two saved stack
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
/// `runProbe` computed.
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
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
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
const suitehash = @import("suitehash.zig");
const MlKem768 = @import("mlkem").MLKem768;
const X25519 = std.crypto.dh.X25519;
const P256c = std.crypto.ecc.P256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128 = std.crypto.core.aes.Aes128;
const NamedGroup = dtls.messages.NamedGroup;

const Step = enum(u8) { c_start, s_hello, s_poll, c_flight2, s_fin, c_send, s_recv, s_send, c_recv, c_install };
const n_steps = 10;

fn isClient(st: Step) bool {
    return switch (st) {
        .c_start, .c_flight2, .c_send, .c_recv, .c_install => true,
        .s_hello, .s_poll, .s_fin, .s_recv, .s_send => false,
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
var inst_c: [48]u8 = undefined;
var inst_s: [48]u8 = undefined;

const app_msg = "dtls kex probe application record";

fn connOf(st: Step) *Connection {
    return if (isClient(st)) &live_client else &live_server;
}

fn stepIn(st: Step) []const u8 {
    return in_store[@backingInt(st)][0..in_len[@backingInt(st)]];
}

fn setIn(st: Step) void {
    @memcpy(in_store[@backingInt(st)][0..out_len], out_buf[0..out_len]);
    in_len[@backingInt(st)] = out_len;
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
        .s_poll => {
            // The retransmission timer: flight 2 re-sealed under the
            // handshake keys in new records (`retransmitFlight`).
            const o = (live_server.poll(5000, &out_buf) catch return failStep()) orelse return failStep();
            out_len = o.len;
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
            const n = live_client.suite.hash().len();
            live_client.installApplicationSecrets(live_client.suite, inst_c[0..n], inst_s[0..n]) catch return failStep();
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
    @memcpy(std.mem.asBytes(connOf(cur_step)), std.mem.asBytes(&pre[@backingInt(cur_step)]));
    rec.reset(cur_seed +% @backingInt(cur_step));
}

/// Walk the handshake once; fill `pre`, the inputs and `step_rec`.
fn reference(cfg_c: dtls.Config, cfg_s: dtls.Config) !void {
    live_client = try Connection.clientInit(cfg_c);
    live_server = try Connection.serverInit(cfg_s);
    in_len = @splat(0);
    for (0..n_steps) |i| {
        const st: Step = @fromBackingInt(@intCast(i));
        cur_step = st;
        @memcpy(std.mem.asBytes(&pre[i]), std.mem.asBytes(connOf(st)));
        prepStep();
        step_failed = false;
        if (st == .c_install) {
            inst_c = pre[@backingInt(Step.s_fin)].pending_ap_client;
            inst_s = pre[@backingInt(Step.s_fin)].pending_ap_server;
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
            .s_poll, .s_fin, .s_recv, .c_recv, .c_install => {},
        }
    }
    try std.testing.expectEqual(dtls.connection.State.connected, live_client.state);
    try std.testing.expectEqual(dtls.connection.State.connected, live_server.state);
}

fn onWire(chunk: []const u8) bool {
    for ([_]Step{ .s_hello, .s_poll, .c_flight2, .s_fin }) |st| {
        if (std.mem.find(u8, stepIn(st), chunk) != null) return true;
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
    // the SHA-384 schedule (48-byte secrets, larger SHA-384 frames).
    .{ .name = "psk aes256gcm sha384", .psk = true, .group = .x25519, .suite = .aes_256_gcm_sha384 },
    .{ .name = "cert x25519 aes256gcm sha384", .psk = false, .group = .x25519, .suite = .aes_256_gcm_sha384 },
    // the CCM suites (the `aesccm` module's CBC-MAC and CTR frames).
    .{ .name = "psk aes128ccm8", .psk = true, .group = .x25519, .suite = .aes_128_ccm_8_sha256 },
    .{ .name = "cert x25519 aes128ccm", .psk = false, .group = .x25519, .suite = .aes_128_ccm_sha256 },
};

const probe_staple = "\x30\x03\x0a\x01\x00"; // OCSPResponse { successful }
const probe_scts = "\x00\x06\x00\x04\x05\x06\x07\x08";

var psk_store: [32]u8 = undefined;
var sk_server: Ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var sk_client: Ecdsa.EcdsaP256Sha256.SecretKey = undefined;

fn configs(comptime set: Set) !struct { c: dtls.Config, s: dtls.Config } {
    const suites = [_]dtls.CipherSuite{set.suite};
    if (set.psk) {
        return .{
            .c = .{ .role = .client, .psk_identity = "device-042", .psk = &psk_store, .psk_hash = comptime set.suite.hash(), .cipher_suites = &suites },
            .s = .{ .role = .server, .psk_identity = "device-042", .psk = &psk_store, .psk_hash = comptime set.suite.hash(), .cipher_suites = &suites },
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
    // OCSP stapling and SCTs (public data) ride the leaf's CertificateEntry:
    // the encoder/decoder paths run inside the probed steps.
    c.request_ocsp = true;
    c.request_scts = true;
    s.cert.?.ocsp_response = probe_staple;
    s.cert.?.sct_list = probe_scts;
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
    const aes = set.suite == .aes_128_gcm_sha256 or set.suite == .aes_128_ccm_sha256 or set.suite == .aes_128_ccm_8_sha256;
    // The suite's hash: SHA-256, or SHA-384 (48-byte secrets) for AES-256-GCM.
    const alg = comptime set.suite.hash();
    const T = suitehash.Types(alg);
    const L = T.n;

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
                const kp = MlKem768.KeyPair.generateDeterministic(chunk[0..MlKem768.seed_length].*);
                n.addImage("ml-kem dk", std.mem.asBytes(&kp.secret_key));
                n.addImage("ml-kem dk", &kp.secret_key.toBytes());
            }
        }
    }

    var eh: [L]u8 = undefined;
    T.Hash.hash("", &eh, .{});
    var dh: [64]u8 = undefined;
    var dh_len: usize = 0;
    var es: [L]u8 = undefined;
    if (set.psk) {
        n.addBig("psk", &psk_store);
        keyschedule.earlySecret(T.Hkdf, &es, &psk_store);
        var bk: [L]u8 = undefined;
        keyschedule.binderKey(T.Hkdf, &bk, &es, &eh);
        n.addBig("binder key", &bk);
        var bk_fin: [L]u8 = undefined;
        keyschedule.deriveFinishedKey(T.Hkdf, L, &bk_fin, &bk);
        n.addBig("binder key", &bk_fin);
    } else {
        const cl = &pre[@backingInt(Step.c_flight2)];
        const sv = &pre[@backingInt(Step.s_fin)];
        const grp = cl.ecdhe_group;
        try std.testing.expectEqual(@backingInt(set.group), grp);
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
                const kp = MlKem768.KeyPair.generateDeterministic(cl.ecdhe_secret[0..MlKem768.seed_length].*);
                const ss_pq = kp.secret_key.decaps(sp[0..MlKem768.ciphertext_length]);
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
        const zero_psk: [L]u8 = @splat(0);
        keyschedule.earlySecret(T.Hkdf, &es, &zero_psk);
        n.addBig("server sign key", &cert_kat.server_secret_key_bytes);
        if (set.mutual) n.addBig("client sign key", &cert_kat.client_secret_key_bytes);
        try liveSignatureNeedles(n, set);
    }
    n.addBig("early secret", &es);
    var derived: [L]u8 = undefined;
    keyschedule.deriveSecret(T.Hkdf, &derived, &es, "derived", &eh);
    n.addBig("derived", &derived);
    var hs: [L]u8 = undefined;
    var ms: [L]u8 = undefined;
    keyschedule.deriveHandshakeSecret(T.Hkdf, &hs, &es, &eh, if (set.psk) null else dh[0..dh_len]);
    keyschedule.deriveMasterSecret(T.Hkdf, &ms, &hs, &eh);
    n.addBig("handshake secret", &hs);
    keyschedule.deriveSecret(T.Hkdf, &derived, &hs, "derived", &eh);
    n.addBig("derived", &derived);
    n.addBig("master secret", &ms);

    // Traffic secrets from the live server, after ServerHello..Finished.
    const sv = &pre[@backingInt(Step.s_fin)];
    n.addBig("hs traffic c", sv.hs_traffic_client[0..L]);
    n.addBig("hs traffic s", sv.hs_traffic_server[0..L]);
    n.addBig("ap traffic c", sv.pending_ap_client[0..L]);
    n.addBig("ap traffic s", sv.pending_ap_server[0..L]);
    var fkey: [L]u8 = undefined;
    keyschedule.deriveFinishedKey(T.Hkdf, L, &fkey, sv.hs_traffic_client[0..L]);
    n.addBig("finished key", &fkey);
    keyschedule.deriveFinishedKey(T.Hkdf, L, &fkey, sv.hs_traffic_server[0..L]);
    n.addBig("finished key", &fkey);
    // The schedule is only a needle if it is the engine's: it must reproduce the
    // application secrets the server derived from it.
    // `L` of each 48-byte `Secret` is live.
    var th_buf: [48]u8 = undefined;
    const th = sv.transcript.currentHash(alg, &th_buf);
    var ap_c: [L]u8 = undefined;
    var ap_s: [L]u8 = undefined;
    keyschedule.deriveApplicationTrafficSecrets(T.Hkdf, &ap_c, &ap_s, &ms, th);
    try std.testing.expectEqualSlices(u8, sv.pending_ap_client[0..L], &ap_c);
    try std.testing.expectEqualSlices(u8, sv.pending_ap_server[0..L], &ap_s);

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

// ── the ECDSA nonce of the live CertificateVerify ──────────────────────────
//
// The first test measures `certverify.sign` on a fixed transcript hash; here the
// nonce of the signature a live handshake actually SENT becomes a needle too.
// The CertificateVerify is read back from the wire: the sender's epoch-2 records
// are opened with its handshake keys (as the receiver does), the transcript is
// rebuilt from the messages, and `k` is solved from the signature over exactly
// that content (`ecdsaNeedles`). Teeth: each signature must verify under the
// sender's public key, and the rebuilt transcript through the server Finished
// must equal the server's own.

const record = @import("record.zig");
const aead = @import("aead.zig");
const hs_frame = @import("handshake.zig");
const Aes128Gcm = @import("aesgcm").Aes128Gcm;
const Aes256Gcm = @import("aesgcm").Aes256Gcm;
const Aes128Ccm = @import("aesccm").Aes128Ccm;
const Aes128Ccm8 = @import("aesccm").Aes128Ccm8;
const ChaCha20Poly1305 = @import("chachapoly").ChaCha20Poly1305;

const Msg = struct { t: u8, body: []const u8 };
const max_msgs = 12;
const MsgList = struct {
    m: [max_msgs]Msg = undefined,
    len: usize = 0,
    plain: [6][2048]u8 = undefined,
};
var flight_ch: MsgList = .{};
var flight_sv: MsgList = .{};
var flight_cl: MsgList = .{};

/// One epoch-2 record opened with the sender's handshake `keys`: the
/// DTLSInnerPlaintext content, or empty for a non-handshake record (ACK).
fn openEpoch2(suite: dtls.CipherSuite, keys: anytype, rec_bytes: []const u8, seq: u64, out: []u8) ![]const u8 {
    const dec = try record.decodeUnified(rec_bytes, 0);
    const hdr_len = dec.consumed;
    const ct = rec_bytes[hdr_len..][0..dec.hdr.length.?];
    var hdr: [8]u8 = undefined;
    @memcpy(hdr[0..hdr_len], rec_bytes[0..hdr_len]);
    const nseq: usize = if (dec.hdr.seq_len == .short) 1 else 2;
    const seq_bytes = hdr[1..][0..nseq];
    switch (suite) {
        .aes_128_gcm_sha256, .aes_128_ccm_sha256, .aes_128_ccm_8_sha256 => try aead.decryptSequenceNumberAes(keys.sn_key[0..16], ct[0..16], seq_bytes),
        .aes_256_gcm_sha384 => try aead.decryptSequenceNumberAes(keys.sn_key[0..32], ct[0..16], seq_bytes),
        .chacha20_poly1305_sha256 => try aead.decryptSequenceNumberChaCha20(keys.sn_key[0..32], ct[0..16], seq_bytes),
    }
    const low: u64 = if (nseq == 1) seq_bytes[0] else std.mem.readInt(u16, hdr[1..3], .big);
    const mask: u64 = if (nseq == 1) 0xff else 0xffff;
    try std.testing.expectEqual(seq & mask, low);
    const len = switch (suite) {
        .aes_128_gcm_sha256 => try aead.Protection(Aes128Gcm).unprotect(keys.key[0..16], keys.iv, 2, seq, ct, hdr[0..hdr_len], out),
        .aes_256_gcm_sha384 => try aead.Protection(Aes256Gcm).unprotect(keys.key[0..32], keys.iv, 2, seq, ct, hdr[0..hdr_len], out),
        .chacha20_poly1305_sha256 => try aead.Protection(ChaCha20Poly1305).unprotect(keys.key[0..32], keys.iv, 2, seq, ct, hdr[0..hdr_len], out),
        .aes_128_ccm_sha256 => try aead.Protection(Aes128Ccm).unprotect(keys.key[0..16], keys.iv, 2, seq, ct, hdr[0..hdr_len], out),
        .aes_128_ccm_8_sha256 => try aead.Protection(Aes128Ccm8).unprotect(keys.key[0..16], keys.iv, 2, seq, ct, hdr[0..hdr_len], out),
    };
    var end = len;
    while (end > 0 and out[end - 1] == 0) end -= 1;
    try std.testing.expect(end > 0);
    if (out[end - 1] != 22) return out[0..0];
    return out[0 .. end - 1];
}

/// The handshake messages of a flight, in order: epoch-0 records as sent,
/// epoch-2 ones opened with `keys` (record numbers from 0).
fn flightMessages(suite: dtls.CipherSuite, keys: anytype, records: []const u8, list: *MsgList) !void {
    list.len = 0;
    var rest = records;
    var seq: u64 = 0;
    var slot: usize = 0;
    while (rest.len != 0) {
        const sp = record.nextDatagram(rest, 1);
        const r = sp.datagram;
        rest = sp.rest;
        var plain: []const u8 = undefined;
        if (r[0] == 22) {
            plain = r[record.plaintext_header_len..];
        } else if (r[0] & 0xe0 == 0x20) {
            plain = try openEpoch2(suite, keys, r, seq, &list.plain[slot]);
            slot += 1;
            seq += 1;
        } else continue;
        while (plain.len >= hs_frame.header_len) {
            const h = try hs_frame.decodeHeader(plain);
            try std.testing.expect(h.fragment_offset == 0 and h.fragment_length == h.length);
            list.m[list.len] = .{ .t = h.msg_type, .body = plain[hs_frame.header_len..][0..h.length] };
            list.len += 1;
            plain = plain[hs_frame.header_len + h.length ..];
        }
    }
}

/// Appends `list` to `t`; a CertificateVerify on the way is checked and its
/// nonce added. Returns how many there were.
fn walkFlight(n: *Needles, t: *suitehash.Transcript, comptime alg: suitehash.HashAlg, list: *const MsgList, side: certverify.Side, sk_bytes: *const [32]u8) !usize {
    var cvs: usize = 0;
    for (list.m[0..list.len]) |m| {
        if (m.t == 15) {
            var th_buf: [48]u8 = undefined;
            const th = t.currentHash(alg, &th_buf);
            var content_buf: [certverify.max_signed_content_len]u8 = undefined;
            const content = try certverify.buildSignedContent(side, th, &content_buf);
            try std.testing.expectEqual(@as(u16, 0x0403), std.mem.readInt(u16, m.body[0..2], .big));
            const sig_len_cv = std.mem.readInt(u16, m.body[2..4], .big);
            const sig = m.body[4..][0..sig_len_cv];
            const kp = try Ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(try Ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(sk_bytes.*));
            try (try Ecdsa.EcdsaP256Sha256.Signature.fromDer(sig)).verify(content, kp.public_key);
            try ecdsaNeedles(P256, Ecdsa.EcdsaP256Sha256, Sha256, n, sk_bytes, content, sig);
            cvs += 1;
        }
        t.append(m.t, m.body);
    }
    return cvs;
}

fn liveSignatureNeedles(n: *Needles, comptime set: Set) !void {
    const alg = comptime set.suite.hash();
    const sv = &pre[@backingInt(Step.s_fin)];
    try flightMessages(set.suite, sv.hs_write_keys, stepIn(.s_hello), &flight_ch);
    try flightMessages(set.suite, sv.hs_write_keys, stepIn(.c_flight2), &flight_sv);
    var t: suitehash.Transcript = .{};
    t.select(alg);
    try std.testing.expectEqual(@as(usize, 0), try walkFlight(n, &t, alg, &flight_ch, .client, &cert_kat.client_secret_key_bytes));
    try std.testing.expectEqual(@as(usize, 1), try walkFlight(n, &t, alg, &flight_sv, .server, &cert_kat.server_secret_key_bytes));
    var a: [48]u8 = undefined;
    var b: [48]u8 = undefined;
    try std.testing.expectEqualSlices(u8, sv.transcript.currentHash(alg, &a), t.currentHash(alg, &b));
    if (set.mutual) {
        try flightMessages(set.suite, sv.hs_read_keys, stepIn(.s_fin), &flight_cl);
        try std.testing.expectEqual(@as(usize, 1), try walkFlight(n, &t, alg, &flight_cl, .client, &cert_kat.client_secret_key_bytes));
    }
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

// ═════════════════════════════════════════════════════════════════════════════
// The HelloRetryRequest cookie flow (RFC 9147 §5.1)
// ═════════════════════════════════════════════════════════════════════════════
//
// A handshake whose server answers ClientHello1 with a stateless retry
// (`Config.hello_retry`) and whose ClientHello2 is answered by a second, fresh
// server `Connection` — what a cookie-checking server runs. Steps: the client's
// ClientHello1, the first server's retry, the client's ClientHello2, the second
// server's flight, the client's Finished, the server's last step; each restored
// and re-seeded as above. Needles: the cookie secret and the HMAC state keyed
// with it; the entropy that is not on the wire (and its X25519 images); the PSK
// or the server's signing key and the X25519 shared secret; the handshake and
// application traffic secrets and every record key read from the live
// connections.

const HStep = enum(u8) { c_start, s_hrr, c_hrr, s_hello, c_flight2, s_fin };
const h_n = 6;
var h_server1: Connection = undefined;
var h_pre: [h_n]Connection = undefined;
var h_in: [h_n][6144]u8 = undefined;
var h_in_len: [h_n]usize = @splat(0);
var h_rec: [h_n]Rec = undefined;
var h_cur: HStep = .c_start;
var cookie_secret_store: [32]u8 = undefined;
const h_binding = "198.51.100.7:4433";

fn hConn(st: HStep) *Connection {
    return switch (st) {
        .c_start, .c_hrr, .c_flight2 => &live_client,
        .s_hrr => &h_server1,
        .s_hello, .s_fin => &live_server,
    };
}

fn hIn(i: usize) []const u8 {
    return h_in[i][0..h_in_len[i]];
}

/// API adapter for the retry flow.
fn hDoStep(st: HStep) void {
    const ent: dtls.Entropy = .{ .seeded_for_test = rec.random() };
    if (st == .c_start) {
        const o = live_client.startHandshake(ent, 0, &out_buf) catch return failStep();
        out_len = o.len;
        return;
    }
    const r = hConn(st).handleFlight(hIn(@backingInt(st)), ent, 0, &out_buf) catch return failStep();
    out_len = r.out.len;
}

noinline fn hCallStep() void {
    hDoStep(h_cur);
}

fn hPrep() void {
    @memcpy(std.mem.asBytes(hConn(h_cur)), std.mem.asBytes(&h_pre[@backingInt(h_cur)]));
    rec.reset(cur_seed +% @backingInt(h_cur));
}

/// Walk the retry handshake once; each step's output is the next one's input.
fn hReference(cfg_c: dtls.Config, cfg_s: dtls.Config) !void {
    live_client = try Connection.clientInit(cfg_c);
    h_server1 = try Connection.serverInit(cfg_s);
    live_server = try Connection.serverInit(cfg_s);
    h_in_len = @splat(0);
    for (0..h_n) |i| {
        const st: HStep = @fromBackingInt(@intCast(i));
        h_cur = st;
        @memcpy(std.mem.asBytes(&h_pre[i]), std.mem.asBytes(hConn(st)));
        hPrep();
        step_failed = false;
        hDoStep(st);
        try std.testing.expect(!step_failed);
        h_rec[i] = rec;
        if (i + 1 < h_n) {
            @memcpy(h_in[i + 1][0..out_len], out_buf[0..out_len]);
            h_in_len[i + 1] = out_len;
        }
    }
    try std.testing.expect(h_server1.sawHelloRetryRequest());
    try std.testing.expect(live_server.sawHelloRetryRequest());
    try std.testing.expectEqual(dtls.connection.State.connected, live_client.state);
    try std.testing.expectEqual(dtls.connection.State.connected, live_server.state);
}

fn hOnWire(chunk: []const u8) bool {
    for (0..h_n) |i| {
        if (std.mem.find(u8, hIn(i), chunk) != null) return true;
    }
    return false;
}

fn hBuildNeedles(n: *Needles, comptime set: Set) ![LEAK]u8 {
    n.len = 0;
    n.n_names = 0;
    const aes = set.suite == .aes_128_gcm_sha256 or set.suite == .aes_128_ccm_sha256 or set.suite == .aes_128_ccm_8_sha256;
    const L = comptime set.suite.hash().len();
    for (0..h_n) |i| {
        const r = &h_rec[i];
        for (0..r.n_ent) |e| {
            const chunk = r.log[r.ent_off[e]..][0..r.ent_len[e]];
            if (hOnWire(chunk)) continue;
            n.addBig("entropy", chunk);
            if (chunk.len == 32) {
                var cl: [32]u8 = chunk[0..32].*;
                cl[0] &= 248;
                cl[31] &= 127;
                cl[31] |= 64;
                n.addBig("x25519 scalar", &cl);
            }
        }
    }
    n.addBig("cookie secret", &cookie_secret_store);
    const hm = std.crypto.auth.hmac.sha2.HmacSha256.init(&cookie_secret_store);
    n.addImage("cookie hmac", std.mem.asBytes(&hm));
    const sv = &h_pre[@backingInt(HStep.s_fin)];
    if (set.psk) {
        n.addBig("psk", &psk_store);
    } else {
        const cl = &h_pre[@backingInt(HStep.c_flight2)];
        n.addBig("ecdhe secret", cl.ecdhe_secret[0..32]);
        const ss = try X25519.scalarmult(cl.ecdhe_secret[0..32].*, sv.ecdhe_public[0..32].*);
        n.addBig("dh shared", &ss);
        n.addBig("server sign key", &cert_kat.server_secret_key_bytes);
    }
    n.addBig("hs traffic c", sv.hs_traffic_client[0..L]);
    n.addBig("hs traffic s", sv.hs_traffic_server[0..L]);
    n.addBig("ap traffic c", sv.pending_ap_client[0..L]);
    n.addBig("ap traffic s", sv.pending_ap_server[0..L]);
    addDir(n, sv.hs_write_keys, aes);
    addDir(n, sv.hs_read_keys, aes);
    addDir(n, live_client.write_keys, aes);
    addDir(n, live_client.read_keys, aes);
    addDir(n, live_server.write_keys, aes);
    addDir(n, live_server.read_keys, aes);
    var ctl: [LEAK]u8 = undefined;
    Sha256.hash("hrr " ++ set.name, &ctl, .{});
    n.addBig("control", &ctl);
    n.sort();
    return ctl;
}

test "STACKPROBE: no cookie-secret, ECDHE, traffic-secret or record-key residue on the dead stack through a HelloRetryRequest cookie handshake" {
    try skipUnlessOptimized();
    const hrr_sets = [_]Set{ sets[0], sets[2] }; // psk aes128gcm, cert x25519 aes128gcm
    var bad: usize = 0;
    inline for (hrr_sets, 0..) |set, si| {
        Sha256.hash(set.name, &psk_store, .{});
        Sha256.hash("cookie " ++ set.name, &cookie_secret_store, .{});
        cur_seed = 0xC00C_0000 + si * 64;
        var cfg = try configs(set);
        cfg.s.hello_retry = .{ .cookie_secret = &cookie_secret_store, .peer_binding = h_binding };
        try hReference(cfg.c, cfg.s);
        leak_src = try hBuildNeedles(&needles_store, set);
        prep_fn = hPrep;
        inline for (comptime std.meta.tags(HStep)) |st| {
            h_cur = st;
            bad += try runProbe("hrr " ++ set.name ++ " " ++ @tagName(st), hCallStep, &needles_store);
        }
        prep_fn = noPrep;
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

// ═════════════════════════════════════════════════════════════════════════════
// Session resumption with 0-RTT (RFC 8446 §2.2, §2.3 over RFC 9147)
// ═════════════════════════════════════════════════════════════════════════════
//
// A ticket from an unprobed full handshake (server `Config.tickets` over a
// STEK ring, ALPN negotiated), then a resumption that sends early data: the
// client's ClientHello + epoch-1 records (binder, early traffic keys), the
// server's flight (ticket opened, binder checked, early records read), the
// client's Finished, the server's last step (a fresh ticket sealed) and the
// client taking that ticket. Needles: the ticket PSK, its early secret and
// binder key, the STEK and its AES-256 round keys, the entropy not on the
// wire, the ECDHE secret and shared value, the early, handshake and
// application traffic secrets and record keys, and the new ticket's PSK.

const tlsresume = @import("tlsresume");
const Aes256 = std.crypto.core.aes.Aes256;

const RStep = enum(u8) { c_start, s_hello, c_flight2, s_fin, c_ticket };
const r_n = 5;
var r_pre: [r_n]Connection = undefined;
var r_in: [r_n][6144]u8 = undefined;
var r_in_len: [r_n]usize = @splat(0);
var r_rec: [r_n]Rec = undefined;
var r_cur: RStep = .c_start;
var r_ring: tlsresume.stek.DefaultRing = undefined;
var r_tkr: dtls.StekTicketer(tlsresume.stek.DefaultRing) = undefined;
var r_ticket: dtls.SessionTicket = undefined;
var stek_key_store: [32]u8 = undefined;
const r_early = "dtls 0-RTT probe early data";

fn admitAll(_: ?*anyopaque, _: []const u8, _: i64) bool {
    return true;
}

fn rConn(st: RStep) *Connection {
    return switch (st) {
        .c_start, .c_flight2, .c_ticket => &live_client,
        .s_hello, .s_fin => &live_server,
    };
}

fn rIn(i: usize) []const u8 {
    return r_in[i][0..r_in_len[i]];
}

/// The records of `bytes`, one `recv` each; ACKs and post-handshake messages
/// are what arrives here.
fn deliverRecords(to: *Connection, bytes: []const u8) bool {
    var rest = bytes;
    while (rest.len != 0) {
        const sp = record.nextDatagram(rest, 1);
        rest = sp.rest;
        if (to.recv(sp.datagram, &plain_buf)) |_| return false else |e| switch (e) {
            error.ReceivedAck, error.ReceivedPostHandshakeMessage => {},
            else => return false,
        }
    }
    return true;
}

/// API adapter for the resumption flow.
fn rDoStep(st: RStep) void {
    const ent: dtls.Entropy = .{ .seeded_for_test = rec.random() };
    switch (st) {
        .c_start => {
            const o = live_client.startHandshake(ent, 0, &out_buf) catch return failStep();
            out_len = o.len;
        },
        .c_ticket => {
            if (!deliverRecords(&live_client, rIn(@backingInt(st)))) return failStep();
            out_len = 0;
        },
        else => {
            const r = rConn(st).handleFlight(rIn(@backingInt(st)), ent, 0, &out_buf) catch return failStep();
            out_len = r.out.len;
        },
    }
}

noinline fn rCallStep() void {
    rDoStep(r_cur);
}

fn rPrep() void {
    @memcpy(std.mem.asBytes(rConn(r_cur)), std.mem.asBytes(&r_pre[@backingInt(r_cur)]));
    rec.reset(cur_seed +% @backingInt(r_cur));
}

/// The unprobed full handshake that issues `r_ticket`.
fn rTicketHandshake(cfg_c: dtls.Config, cfg_s: dtls.Config) !void {
    live_client = try Connection.clientInit(cfg_c);
    live_server = try Connection.serverInit(cfg_s);
    rec.reset(cur_seed +% 0x100);
    const ent: dtls.Entropy = .{ .seeded_for_test = rec.random() };
    var b1: [6144]u8 = undefined;
    var b2: [6144]u8 = undefined;
    const ch = try live_client.startHandshake(ent, 0, &b1);
    const f2 = try live_server.handleFlight(ch, ent, 0, &b2);
    const cf = try live_client.handleFlight(f2.out, ent, 0, &b1);
    const sr = try live_server.handleFlight(cf.out, ent, 0, &b2);
    try std.testing.expect(sr.done and deliverRecords(&live_client, sr.out));
    r_ticket = (live_client.sessionTicket() orelse return error.TestNoTicket).*;
}

/// Walk the resumption once; each step's output is the next one's input.
fn rReference(cfg_c: dtls.Config, cfg_s: dtls.Config) !void {
    live_client = try Connection.clientInit(cfg_c);
    live_server = try Connection.serverInit(cfg_s);
    r_in_len = @splat(0);
    for (0..r_n) |i| {
        const st: RStep = @fromBackingInt(@intCast(i));
        r_cur = st;
        @memcpy(std.mem.asBytes(&r_pre[i]), std.mem.asBytes(rConn(st)));
        rPrep();
        step_failed = false;
        rDoStep(st);
        try std.testing.expect(!step_failed);
        r_rec[i] = rec;
        if (i + 1 < r_n) {
            @memcpy(r_in[i + 1][0..out_len], out_buf[0..out_len]);
            r_in_len[i + 1] = out_len;
        }
    }
    try std.testing.expectEqual(dtls.connection.State.connected, live_client.state);
    try std.testing.expectEqual(dtls.connection.State.connected, live_server.state);
    try std.testing.expect(live_server.resumed() and live_client.resumed());
    try std.testing.expect(live_server.earlyDataAccepted() and live_client.earlyDataAccepted());
    try std.testing.expectEqualSlices(u8, r_early, live_server.earlyData());
    const fresh = live_client.sessionTicket() orelse return error.TestNoTicket;
    try std.testing.expect(!std.mem.eql(u8, fresh.identity(), r_ticket.identity()));
}

fn rOnWire(chunk: []const u8) bool {
    for (0..r_n) |i| {
        if (std.mem.find(u8, rIn(i), chunk) != null) return true;
    }
    return false;
}

fn rBuildNeedles(n: *Needles, comptime set: Set) ![LEAK]u8 {
    n.len = 0;
    n.n_names = 0;
    const aes = set.suite == .aes_128_gcm_sha256 or set.suite == .aes_128_ccm_sha256 or set.suite == .aes_128_ccm_8_sha256;
    const alg = comptime set.suite.hash();
    const L = comptime alg.len();
    for (0..r_n) |i| {
        const r = &r_rec[i];
        for (0..r.n_ent) |e| {
            const chunk = r.log[r.ent_off[e]..][0..r.ent_len[e]];
            if (rOnWire(chunk)) continue;
            n.addBig("entropy", chunk);
            if (chunk.len == 32) {
                var cl: [32]u8 = chunk[0..32].*;
                cl[0] &= 248;
                cl[31] &= 127;
                cl[31] |= 64;
                n.addBig("x25519 scalar", &cl);
            }
        }
    }
    n.addBig("ticket psk", r_ticket.psk[0..L]);
    var es: suitehash.Secret = undefined;
    suitehash.earlySecret(alg, &es, r_ticket.psk[0..L]);
    n.addBig("early secret", es[0..L]);
    var bk: suitehash.Secret = undefined;
    suitehash.resumptionBinderKey(alg, &bk, &es);
    n.addBig("binder key", bk[0..L]);
    n.addBig("stek", &stek_key_store);
    const stek_aes = Aes256.initEnc(stek_key_store);
    n.addImage("stek round keys", std.mem.asBytes(&stek_aes));
    const cl = &r_pre[@backingInt(RStep.c_flight2)];
    const sv = &r_pre[@backingInt(RStep.s_fin)];
    n.addBig("ecdhe secret", cl.ecdhe_secret[0..32]);
    const ss = try X25519.scalarmult(cl.ecdhe_secret[0..32].*, sv.ecdhe_public[0..32].*);
    n.addBig("dh shared", &ss);
    n.addBig("hs traffic c", sv.hs_traffic_client[0..L]);
    n.addBig("hs traffic s", sv.hs_traffic_server[0..L]);
    n.addBig("ap traffic c", sv.pending_ap_client[0..L]);
    n.addBig("ap traffic s", sv.pending_ap_server[0..L]);
    n.addBig("resumption master", live_server.resumption_master[0..L]);
    n.addBig("new ticket psk", live_client.sessionTicket().?.psk[0..L]);
    addDir(n, cl.early_keys, aes);
    addDir(n, sv.early_keys, aes);
    addDir(n, sv.hs_write_keys, aes);
    addDir(n, sv.hs_read_keys, aes);
    addDir(n, live_client.write_keys, aes);
    addDir(n, live_client.read_keys, aes);
    addDir(n, live_server.write_keys, aes);
    addDir(n, live_server.read_keys, aes);
    var ctl: [LEAK]u8 = undefined;
    Sha256.hash("resume " ++ set.name, &ctl, .{});
    n.addBig("control", &ctl);
    n.sort();
    return ctl;
}

test "STACKPROBE: no ticket-PSK, STEK, early-traffic, ECDHE or record-key residue on the dead stack through a 0-RTT resumption" {
    try skipUnlessOptimized();
    const r_sets = [_]Set{ sets[2], sets[6] }; // cert x25519 aes128gcm, cert x25519 aes256gcm sha384
    var bad: usize = 0;
    inline for (r_sets, 0..) |set, si| {
        Sha256.hash("stek " ++ set.name, &stek_key_store, .{});
        r_ring = .init();
        r_ring.rotate(1, &stek_key_store, cert_kat.valid_now_sec);
        r_tkr = .{ .ring = &r_ring };
        cur_seed = 0x0E77_0000 + si * 64;
        var cfg = try configs(set);
        cfg.s.now_sec = cert_kat.valid_now_sec;
        cfg.s.tickets = .{ .ticketer = r_tkr.ticketer(), .max_early_data = 1024, .replay = .{ .admit = admitAll } };
        cfg.c.alpn_protocols = &.{"coap"};
        cfg.s.alpn_protocols = &.{"coap"};
        try rTicketHandshake(cfg.c, cfg.s);
        cfg.c.resumption = &r_ticket;
        cfg.c.early_data = r_early;
        try rReference(cfg.c, cfg.s);
        leak_src = try rBuildNeedles(&needles_store, set);
        prep_fn = rPrep;
        inline for (comptime std.meta.tags(RStep)) |st| {
            r_cur = st;
            bad += try runProbe("resume " ++ set.name ++ " " ++ @tagName(st), rCallStep, &needles_store);
        }
        prep_fn = noPrep;
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
