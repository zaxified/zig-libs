// SPDX-License-Identifier: MIT

//! Tests added by the 2026-11-25 delta mutation run over the code that changed
//! after the 2026-11-18 card (plaintext operands, Galois keys, modulus
//! switching, byte codecs, batch encoder, `maxLogQ`). Each test names the
//! behaviour that no earlier test pinned.

const std = @import("std");
const testing = std.testing;
const params = @import("params.zig");
const Bfv = @import("bfv.zig").Bfv;
const BatchEncoder = @import("batch.zig").BatchEncoder;

fn bitrev(bits: u6, x: usize) usize {
    var r: usize = 0;
    var v = x;
    for (0..bits) |_| {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    return r;
}

test "mutation 2026-11-25: mulScalar and negate act on every component of a 3-component ciphertext" {
    const B = Bfv(params.test_mul);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x7a1);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var rlk: B.RelinKey = undefined;
    inst.genRelinKeyForTest(&kp.sk, rnd, &rlk);
    var a = B.Plaintext.zero(16);
    var b = B.Plaintext.zero(16);
    a.coeffs[0] = 3;
    b.coeffs[1] = 5;
    const ab = inst.mul(&inst.encryptForTest(&kp.pk, &a, rnd), &inst.encryptForTest(&kp.pk, &b, rnd));
    try testing.expectEqual(@as(usize, 3), ab.len);
    const prod = B.Plaintext.mulRef(&a, &b);
    const scaled = inst.decrypt(&kp.sk, &inst.relinearize(&inst.mulScalar(&ab, 3), &rlk));
    for (scaled.coeffs, prod.coeffs) |d, x| try testing.expectEqual(x * 3 % 16, d);
    const neg = inst.decrypt(&kp.sk, &inst.relinearize(&inst.negate(&ab), &rlk));
    for (neg.coeffs, prod.coeffs) |d, x| try testing.expectEqual((16 - x) % 16, d);
}

test "mutation 2026-11-25: mulScalar reduces a scalar of t or more mod t before it multiplies the noise" {
    const B = Bfv(params.test_mul);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x7a2);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var a = B.Plaintext.zero(16);
    a.coeffs[0] = 5;
    a.coeffs[3] = 9;
    const ca = inst.encryptForTest(&kp.pk, &a, rnd);
    // 16 * 2^30 + 3 < q (about 5.1e10), and ≡ 3 (mod t): an unreduced scalar
    // multiplies the noise by 1.7e10, far past the decryption bound.
    const k: u64 = (@as(u64, 16) << 30) + 3;
    const got = inst.decrypt(&kp.sk, &inst.mulScalar(&ca, k));
    for (got.coeffs, a.coeffs) |d, x| try testing.expectEqual(x * 3 % 16, d);
}

test "mutation 2026-11-25: mulPlain lifts plaintext coefficients above a small chain prime" {
    // t = 97 is larger than the first prime 17: a coefficient like 60 must be
    // reduced into the limb before the NTT.
    const P = params.Params{ .n = 8, .t = 97, .primes = &.{ 17, 786433 } };
    const B = Bfv(P);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x7a3);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var a = B.Plaintext.zero(97);
    var m = B.Plaintext.zero(97);
    for (&a.coeffs, 0..) |*c, i| c.* = @intCast(40 + 7 * i);
    m.coeffs[0] = 60;
    m.coeffs[2] = 45;
    const ca = inst.encryptForTest(&kp.pk, &a, rnd);
    const got = inst.decrypt(&kp.sk, &inst.mulPlain(&ca, &m));
    try testing.expectEqualSlices(u64, &B.Plaintext.mulRef(&a, &m).coeffs, &got.coeffs);
}

test "mutation 2026-11-25: genGaloisKey (std.Io path) refuses an even or out-of-range element" {
    const P = params.Params{ .n = 16, .t = 97, .primes = &.{ 65537, 786433 } };
    const B = Bfv(P);
    const inst = try B.init();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var kp: B.KeyPair = undefined;
    inst.keyGen(io, &kp);
    var gk: B.GaloisKey = undefined;
    try testing.expectError(error.InvalidGaloisElement, inst.genGaloisKey(&kp.sk, 4, io, &gk));
    try testing.expectError(error.InvalidGaloisElement, inst.genGaloisKey(&kp.sk, 33, io, &gk));
    try inst.genGaloisKey(&kp.sk, B.galoisElement(1), io, &gk);
    try testing.expectEqual(B.galoisElement(1), gk.g);
}

test "mutation 2026-11-25: modSwitchSecretKey carries the domain tag over" {
    const B = Bfv(params.test_mul);
    const Nx = B.Next;
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x7a4);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var sk2: Nx.SecretKey = .{ .s = Nx.Ring.zero(if (kp.sk.s.domain == .ntt) .coeff else .ntt) };
    B.modSwitchSecretKey(&kp.sk, &sk2);
    try testing.expect(sk2.s.domain == kp.sk.s.domain);
    try testing.expectEqualSlices(u64, &kp.sk.s.limbs[0], &sk2.s.limbs[0]);
}

test "mutation 2026-11-25: modSwitchToNext rounds c/q_last to nearest (exact residues of a known ciphertext)" {
    const B = Bfv(params.test_mul);
    const Nx = B.Next;
    const inst = try B.init();
    const q0: u64 = 65537;
    const ql: u64 = 786433;
    var ct: B.Ciphertext = .{
        .components = .{ B.Ring.zero(.coeff), B.Ring.zero(.coeff), B.Ring.zero(.coeff) },
        .len = 2,
    };
    // c0 coefficient j = k_j * q_last + rem_j, with rem_j above and below q_last/2.
    var want: [16]u64 = undefined;
    for (0..16) |j| {
        const kj: u64 = 1000 + 37 * j;
        const rem: u64 = if (j % 2 == 0) ql / 2 + 1 + 101 * j else ql / 2 - 1 - 53 * j;
        const x: u64 = kj * ql + rem;
        ct.components[0].limbs[0][j] = x % q0;
        ct.components[0].limbs[1][j] = x % ql;
        want[j] = ((x + (ql >> 1)) / ql) % q0;
    }
    const out: Nx.Ciphertext = inst.modSwitchToNext(&ct);
    for (0..16) |j| try testing.expectEqual(want[j], out.components[0].limbs[0][j]);
    for (0..16) |j| try testing.expectEqual(@as(u64, 0), out.components[1].limbs[0][j]);
}

test "mutation 2026-11-25: the codec header carries N, L, the primes, relin_base_log2 and the kind, byte by byte" {
    const P = params.Params{ .n = 16, .t = 97, .primes = &.{ 65537, 786433 } };
    const B = Bfv(P);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x7a5);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var want: [B.codec_header_bytes]u8 = undefined;
    @memcpy(want[0..4], "ZBFV");
    want[4] = 1;
    want[5] = 1;
    std.mem.writeInt(u32, want[6..10], 16, .little);
    want[10] = 2;
    std.mem.writeInt(u64, want[11..19], 97, .little);
    std.mem.writeInt(u64, want[19..27], 65537, .little);
    std.mem.writeInt(u64, want[27..35], 786433, .little);
    want[35] = 8; // Params.relin_base_log2 default
    try testing.expectEqual(@as(usize, 36), B.codec_header_bytes);
    var skb: [B.secret_key_bytes]u8 = undefined;
    B.encodeSecretKey(&kp.sk, &skb);
    try testing.expectEqualSlices(u8, &want, skb[0..want.len]);
    // The kind byte of every object.
    var pkb: [B.public_key_bytes]u8 = undefined;
    B.encodePublicKey(&kp.pk, &pkb);
    try testing.expectEqual(@as(u8, 2), pkb[5]);
    var rlk: B.RelinKey = undefined;
    inst.genRelinKeyForTest(&kp.sk, rnd, &rlk);
    var rlb: [B.relin_key_bytes]u8 = undefined;
    B.encodeRelinKey(&rlk, &rlb);
    try testing.expectEqual(@as(u8, 3), rlb[5]);
    const ct = inst.encryptForTest(&kp.pk, &B.Plaintext.zero(97), rnd);
    var cb: [B.ciphertextBytes(2)]u8 = undefined;
    _ = try B.encodeCiphertext(&ct, &cb);
    try testing.expectEqual(@as(u8, 4), cb[5]);
    try testing.expectEqualSlices(u8, want[6..], cb[6..want.len]);
    var gk: B.GaloisKey = undefined;
    try inst.genGaloisKeyForTest(&kp.sk, B.galoisElement(1), rnd, &gk);
    var gkb: [B.galois_key_bytes]u8 = undefined;
    B.encodeGaloisKey(&gk, &gkb);
    try testing.expectEqual(@as(u8, 5), gkb[5]);
    try testing.expectEqual(@as(u64, 3), std.mem.readInt(u64, gkb[B.codec_header_bytes..][0..8], .little));
}

test "mutation 2026-11-25: a 3-component ciphertext round-trips component by component; a header-only ciphertext is WrongLength" {
    const B = Bfv(params.test_mul);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x7a6);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var a = B.Plaintext.zero(16);
    a.coeffs[0] = 2;
    const ca = inst.encryptForTest(&kp.pk, &a, rnd);
    const c3 = inst.mul(&ca, &ca);
    var buf: [B.ciphertextBytes(3)]u8 = undefined;
    const enc = try B.encodeCiphertext(&c3, &buf);
    const back = try B.decodeCiphertext(enc);
    try testing.expectEqual(@as(usize, 3), back.len);
    for (0..3) |c| try testing.expect(back.components[c].eql(&c3.components[c]));
    // Exactly the header, no component-count byte.
    try testing.expectError(error.WrongLength, B.decodeCiphertext(enc[0..B.codec_header_bytes]));
}

test "mutation 2026-11-25: maxLogQ is the standard's table for every degree and level" {
    const want = [3][6]u16{
        .{ 27, 54, 109, 218, 438, 881 },
        .{ 19, 37, 75, 152, 305, 611 },
        .{ 14, 29, 58, 118, 237, 476 },
    };
    const levels = [_]params.SecurityLevel{ .tc128, .tc192, .tc256 };
    const ns = [_]usize{ 1024, 2048, 4096, 8192, 16384, 32768 };
    for (levels, 0..) |lv, li| for (ns, 0..) |n, ni| {
        try testing.expectEqual(@as(?u16, want[li][ni]), params.maxLogQ(n, lv));
    };
    try testing.expectEqual(@as(?u16, null), params.maxLogQ(512, .tc128));
    try testing.expectEqual(@as(?u16, null), params.maxLogQ(65536, .tc256));
}

test "mutation 2026-11-25: batch slot layout is SEAL's index map: slot s sits at NTT position bitrev((e_s - 1) / 2)" {
    inline for (.{ .{ 8, 17 }, .{ 16, 97 }, .{ 32, 193 } }) |nt| {
        const N = nt[0];
        const B = BatchEncoder(N);
        const enc = try B.init(nt[1]);
        const bits: u6 = @intCast(std.math.log2_int(usize, N));
        for (0..N) |s| {
            try testing.expectEqual(@as(u32, @intCast(bitrev(bits, (B.slotExponent(s) - 1) / 2))), enc.ntt_index[s]);
        }
    }
}

test "mutation 2026-11-25: decodeSlots takes plaintext coefficients mod t" {
    const B = BatchEncoder(8);
    const t: u64 = 17;
    const enc = try B.init(t);
    const vals = [8]u64{ 1, 2, 3, 4, 5, 6, 7, 16 };
    var pt = try enc.encodeSlots(&vals);
    const clean = enc.decodeSlots(&pt);
    try testing.expectEqualSlices(u64, &vals, &clean);
    for (&pt.coeffs, 0..) |*c, j| c.* += t * (1 + j); // same residues, unreduced
    try testing.expectEqualSlices(u64, &vals, &enc.decodeSlots(&pt));
}
