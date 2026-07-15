// SPDX-License-Identifier: MIT
//! kat_sign_test — byte-exact SIGN-side KAT for the filled-in signer
//! (fpr/fft/ffsampling/gaussian). Reproduces the official NIST Round-3
//! signing flow for each embedded vector and asserts the produced nonce +
//! compressed signature field match the vector's `sm` envelope exactly.
//!
//! This isolates the signer from keygen (which stays stubbed): the secret
//! basis (f,g,F) is decoded straight from the vector's `sk`, G is recovered
//! by the NTRU relation (G = g*F/f mod q, reusing poly.zig's NTT), and the
//! per-signature randomness is replayed through a faithful port of the NIST
//! KAT AES-256-CTR-DRBG (KAT/generator/katrng.c) so the nonce and the
//! ChaCha20 signer-PRNG seed are bit-identical to what generated the `sm`.
//!
//! Consumption order per vector (matches PQCgenKAT_sign.c + nist.c):
//!   randombytes_init(seed48); draw 48 (keygen, discarded here); draw 40
//!   (nonce); draw 48 (sign PRNG seed). We feed [nonce ++ signseed] to the
//!   signer's rng, so `signWithRng` consumes the 40-byte nonce and
//!   `ffsampling.sampleSignature` consumes the 48-byte seed — reproducing
//!   the reference exactly.

const std = @import("std");
const falcon = @import("root.zig");
const poly = @import("poly.zig");
const v = @import("kat_vectors.zig");

// ---- NIST KAT AES-256-CTR-DRBG (katrng.c), std AES-256 for the ECB core.

const Drbg = struct {
    key: [32]u8,
    ctr: [16]u8,

    fn ecb(key: *const [32]u8, in: *const [16]u8, out: *[16]u8) void {
        const ctx = std.crypto.core.aes.Aes256.initEnc(key.*);
        ctx.encrypt(out, in);
    }

    fn incV(ctr: *[16]u8) void {
        var j: usize = 16;
        while (j > 0) {
            j -= 1;
            if (ctr[j] == 0xff) {
                ctr[j] = 0;
            } else {
                ctr[j] += 1;
                break;
            }
        }
    }

    fn update(self: *Drbg, provided: ?*const [48]u8) void {
        var tmp: [48]u8 = undefined;
        var i: usize = 0;
        while (i < 3) : (i += 1) {
            incV(&self.ctr);
            var blk: [16]u8 = undefined;
            ecb(&self.key, &self.ctr, &blk);
            @memcpy(tmp[16 * i .. 16 * i + 16], &blk);
        }
        if (provided) |pd| {
            for (&tmp, pd) |*t, p| t.* ^= p;
        }
        @memcpy(&self.key, tmp[0..32]);
        @memcpy(&self.ctr, tmp[32..48]);
    }

    fn init(seed: *const [48]u8) Drbg {
        var d: Drbg = .{ .key = [_]u8{0} ** 32, .ctr = [_]u8{0} ** 16 };
        d.update(seed);
        return d;
    }

    fn bytes(self: *Drbg, out: []u8) void {
        var i: usize = 0;
        var remaining = out.len;
        while (remaining > 0) {
            incV(&self.ctr);
            var blk: [16]u8 = undefined;
            ecb(&self.key, &self.ctr, &blk);
            const take = @min(remaining, 16);
            @memcpy(out[i .. i + take], blk[0..take]);
            i += take;
            remaining -= take;
        }
        self.update(null);
    }
};

// ---- A std.Random that replays a fixed byte buffer (nonce ++ signseed).

const FixedRng = struct {
    buf: []const u8,
    pos: usize = 0,

    fn fill(self: *FixedRng, dst: []u8) void {
        std.debug.assert(self.pos + dst.len <= self.buf.len);
        @memcpy(dst, self.buf[self.pos .. self.pos + dst.len]);
        self.pos += dst.len;
    }

    fn random(self: *FixedRng) std.Random {
        return std.Random.init(self, FixedRng.fill);
    }
};

// ---- G = g*F/f mod q, centered; reuses poly.zig's NTT. (complete_private.)

fn powm(base: u32, exp: u32) u32 {
    var r: u32 = 1;
    var b = base % poly.q;
    var e = exp;
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) r = (r * b) % poly.q;
        b = (b * b) % poly.q;
    }
    return r;
}

fn computeG(comptime Ring: type, f: *const [Ring.n]i8, g: *const [Ring.n]i8, big_f: *const [Ring.n]i8) ![Ring.n]i8 {
    var ff = Ring.fromSmall(f);
    var gg = Ring.fromSmall(g);
    var ff2 = Ring.fromSmall(big_f);
    Ring.ntt(&ff);
    Ring.ntt(&gg);
    Ring.ntt(&ff2);
    var gntt: Ring.Poly = undefined;
    for (0..Ring.n) |u| {
        if (ff[u] == 0) return error.NotInvertible;
        const inv = powm(ff[u], poly.q - 2);
        const num = (@as(u32, gg[u]) * @as(u32, ff2[u])) % poly.q;
        gntt[u] = @intCast((num * inv) % poly.q);
    }
    Ring.intt(&gntt);
    var out: [Ring.n]i8 = undefined;
    for (0..Ring.n) |u| {
        var w: i32 = gntt[u];
        if (w > poly.q / 2) w -= poly.q;
        if (w < -127 or w > 127) return error.BadG;
        out[u] = @intCast(w);
    }
    return out;
}

fn hexAlloc(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn runVector(comptime Ring: type, comptime Codec: type, comptime Signer: type, sig_bound: u64, sig_header: u8, vec: v.Vector) !void {
    const gpa = std.testing.allocator;
    const seed = try hexAlloc(gpa, vec.seed);
    defer gpa.free(seed);
    const msg = try hexAlloc(gpa, vec.msg);
    defer gpa.free(msg);
    const sk = try hexAlloc(gpa, vec.sk);
    defer gpa.free(sk);
    const sm = try hexAlloc(gpa, vec.sm);
    defer gpa.free(sm);
    try std.testing.expectEqual(@as(usize, 48), seed.len);

    // Extract expected nonce + signature field from the sm envelope.
    const sig_len = (@as(usize, sm[0]) << 8) | sm[1];
    const want_nonce = sm[2 .. 2 + falcon.nonce_length];
    const want_sig = sm[sm.len - sig_len ..];
    try std.testing.expectEqual(sig_header, want_sig[0]);

    // Replay the DRBG: keygen seed (48), nonce (40), sign seed (48).
    var seed48: [48]u8 = undefined;
    @memcpy(&seed48, seed[0..48]);
    var drbg = Drbg.init(&seed48);
    var discard: [48]u8 = undefined;
    drbg.bytes(&discard); // keygen seed (separate randombytes call)
    // The reference draws the nonce and the sign-PRNG seed in TWO separate
    // randombytes() calls (each reseeds the DRBG), so they must not be
    // fused into one draw.
    var rng_stream: [falcon.nonce_length + 48]u8 = undefined;
    drbg.bytes(rng_stream[0..falcon.nonce_length]); // nonce (40)
    drbg.bytes(rng_stream[falcon.nonce_length..]); // sign seed (48)

    // Decode the secret basis and recover G.
    const dsk = if (Ring.logn == 9)
        try falcon.SecretKey.fromBytes(sk[0..falcon.SecretKey.encoded_length])
    else
        try falcon.SecretKey1024.fromBytes(sk[0..falcon.SecretKey1024.encoded_length]);
    const big_g = try computeG(Ring, &dsk.f, &dsk.g, &dsk.big_f);

    const tree = falcon.ffsampling.buildTree(Ring, &dsk.f, &dsk.g, &dsk.big_f, &big_g);

    // Sign with the replayed randomness.
    var fixed = FixedRng{ .buf = &rng_stream };
    var nonce_out: [falcon.nonce_length]u8 = undefined;
    var sig_out: [2000]u8 = undefined;
    const len = try Signer.signWithRng(&tree, msg, fixed.random(), &nonce_out, &sig_out, sig_bound);

    try std.testing.expectEqualSlices(u8, want_nonce, &nonce_out);
    try std.testing.expectEqualSlices(u8, want_sig, sig_out[0..len]);
    _ = Codec;
}

test "Falcon-512 SIGN KAT: byte-exact nonce + compressed signature" {
    const Ring = poly.Ring512;
    const Signer = falcon.sign.Signer(Ring);
    for (v.falcon512) |vec| {
        try runVector(Ring, falcon.codec.Codec512, Signer, falcon.sig_bound, falcon.sig_header, vec);
    }
}

test "Falcon-1024 SIGN KAT: byte-exact nonce + compressed signature" {
    const Ring = poly.Ring1024;
    const Signer = falcon.sign.Signer(Ring);
    for (v.falcon1024) |vec| {
        try runVector(Ring, falcon.codec.Codec1024, Signer, falcon.sig_bound_1024, falcon.sig_header_1024, vec);
    }
}

// Sign an arbitrary (non-KAT) message with a KAT-derived key and verify it
// through the module's own (KAT-verified) verify path — end-to-end signer
// self-consistency, independent of keygen and of byte-exact reproduction.
// This is what keygen_sign_test.zig's "randomized sign -> verify" checks,
// minus the (still-stubbed) keygen step.
fn signVerifyRoundTrip(
    comptime Ring: type,
    comptime PublicKey: type,
    comptime SecretKey: type,
    comptime Signer: type,
    sig_bound: u64,
    vec: v.Vector,
) !void {
    const gpa = std.testing.allocator;
    const sk = try hexAlloc(gpa, vec.sk);
    defer gpa.free(sk);
    const dsk = try SecretKey.fromBytes(sk[0..SecretKey.encoded_length]);
    const big_g = try computeG(Ring, &dsk.f, &dsk.g, &dsk.big_f);
    const tree = falcon.ffsampling.buildTree(Ring, &dsk.f, &dsk.g, &dsk.big_f, &big_g);
    const pk: PublicKey = try dsk.publicKey();

    var prng = std.Random.DefaultPrng.init(0xfa1c04);
    const rng = prng.random();
    const message = "the quick brown fox jumps over the lazy dog";
    var nonce_out: [falcon.nonce_length]u8 = undefined;
    var sig_out: [2000]u8 = undefined;
    const len = try Signer.signWithRng(&tree, message, rng, &nonce_out, &sig_out, sig_bound);
    try pk.verify(message, &nonce_out, sig_out[0..len]);
}

test "Falcon-512 sign -> verify round trip (KAT-derived key, arbitrary message)" {
    try signVerifyRoundTrip(poly.Ring512, falcon.PublicKey, falcon.SecretKey, falcon.sign.Signer(poly.Ring512), falcon.sig_bound, v.falcon512[0]);
}

test "Falcon-1024 sign -> verify round trip (KAT-derived key, arbitrary message)" {
    try signVerifyRoundTrip(poly.Ring1024, falcon.PublicKey1024, falcon.SecretKey1024, falcon.sign.Signer(poly.Ring1024), falcon.sig_bound_1024, v.falcon1024[0]);
}
