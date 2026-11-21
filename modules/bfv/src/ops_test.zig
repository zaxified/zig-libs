// SPDX-License-Identifier: MIT

//! End-to-end tests of the plaintext-operand ops, batch encoding with Galois
//! rotations, modulus switching, the byte codecs and the standard-level
//! parameter chains. Every check decrypts and compares against the
//! plaintext-space reference (`encode.zig`'s `addRef`/`mulRef`, or the slot
//! permutation a rotation must produce).

const std = @import("std");
const testing = std.testing;
const params = @import("params.zig");
const Bfv = @import("bfv.zig").Bfv;
const BatchEncoder = @import("batch.zig").BatchEncoder;

/// `N = 16`, `t = 97` (prime, `≡ 1 mod 32`: batching), `test_mul`'s chain.
/// Correctness-only, like every toy set.
const test_batch = params.Params{ .n = 16, .t = 97, .primes = &.{ 65537, 786433 } };

fn randomPlain(comptime B: type, rnd: std.Random) B.Plaintext {
    var pt = B.Plaintext.zero(B.parameters.t);
    for (&pt.coeffs) |*c| c.* = rnd.uintLessThan(u64, B.parameters.t);
    return pt;
}

test "addPlain / subPlain / mulPlain / mulScalar / negate decrypt to the plaintext-space result" {
    const B = Bfv(params.test_mul);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x0b5);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    const t = params.test_mul.t;
    for (0..8) |_| {
        const a = randomPlain(B, rnd);
        const m = randomPlain(B, rnd);
        const ca = inst.encryptForTest(&kp.pk, &a, rnd);

        const sum = inst.decrypt(&kp.sk, &inst.addPlain(&ca, &m));
        try testing.expectEqualSlices(u64, &B.Plaintext.addRef(&a, &m).coeffs, &sum.coeffs);

        const diff = inst.decrypt(&kp.sk, &inst.subPlain(&ca, &m));
        for (diff.coeffs, a.coeffs, m.coeffs) |d, x, y| try testing.expectEqual((x + t - y) % t, d);

        const prod = inst.decrypt(&kp.sk, &inst.mulPlain(&ca, &m));
        try testing.expectEqualSlices(u64, &B.Plaintext.mulRef(&a, &m).coeffs, &prod.coeffs);

        const k = rnd.uintLessThan(u64, 3 * t); // reduced mod t inside
        const scaled = inst.decrypt(&kp.sk, &inst.mulScalar(&ca, k));
        for (scaled.coeffs, a.coeffs) |d, x| try testing.expectEqual(x * (k % t) % t, d);

        const neg = inst.decrypt(&kp.sk, &inst.negate(&ca));
        for (neg.coeffs, a.coeffs) |d, x| try testing.expectEqual((t - x) % t, d);
    }
}

test "mulPlain on a 3-component (post-multiply) ciphertext, then relinearize" {
    const B = Bfv(params.test_mul);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x3c0);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var rlk: B.RelinKey = undefined;
    inst.genRelinKeyForTest(&kp.sk, rnd, &rlk);
    var a = B.Plaintext.zero(16);
    var b = B.Plaintext.zero(16);
    var m = B.Plaintext.zero(16);
    a.coeffs[0] = 3;
    b.coeffs[1] = 5;
    m.coeffs[2] = 7;
    const ab = inst.mul(&inst.encryptForTest(&kp.pk, &a, rnd), &inst.encryptForTest(&kp.pk, &b, rnd));
    const abm = inst.relinearize(&inst.mulPlain(&ab, &m), &rlk);
    const want = B.Plaintext.mulRef(&B.Plaintext.mulRef(&a, &b), &m);
    try testing.expectEqualSlices(u64, &want.coeffs, &inst.decrypt(&kp.sk, &abm).coeffs);
}

test "batching + Galois: row rotations left/right and the row swap, slot-wise multiply" {
    const B = Bfv(test_batch);
    const E = BatchEncoder(16);
    const inst = try B.init();
    const enc = try E.init(test_batch.t);
    var prng = std.Random.DefaultPrng.init(0x6a1);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var vals: [16]u64 = undefined;
    for (&vals, 0..) |*x, i| x.* = @intCast(i * 5 + 1);
    const ct = inst.encryptForTest(&kp.pk, &(try enc.encodeSlots(&vals)), rnd);
    const row = E.row_size;

    for ([_]i64{ 1, 3, -1, 7, 8 }) |steps| {
        var gk: B.GaloisKey = undefined;
        try inst.genGaloisKeyForTest(&kp.sk, B.galoisElement(steps), rnd, &gk);
        const got = enc.decodeSlots(&inst.decrypt(&kp.sk, &inst.applyGalois(&ct, &gk)));
        const k: usize = @intCast(@mod(steps, @as(i64, row)));
        for (0..row) |c| {
            try testing.expectEqual(vals[(c + k) % row], got[c]);
            try testing.expectEqual(vals[row + (c + k) % row], got[row + c]);
        }
    }
    var swap: B.GaloisKey = undefined;
    try inst.genGaloisKeyForTest(&kp.sk, B.galois_row_swap, rnd, &swap);
    const swapped = enc.decodeSlots(&inst.decrypt(&kp.sk, &inst.applyGalois(&ct, &swap)));
    try testing.expectEqualSlices(u64, vals[row..], swapped[0..row]);
    try testing.expectEqualSlices(u64, vals[0..row], swapped[row..]);

    // Slot-wise product with a batch-encoded plaintext operand.
    var w: [16]u64 = undefined;
    for (&w, 0..) |*x, i| x.* = @intCast((i * 7 + 3) % 97);
    const prod = enc.decodeSlots(&inst.decrypt(&kp.sk, &inst.mulPlain(&ct, &(try enc.encodeSlots(&w)))));
    for (0..16) |s| try testing.expectEqual(vals[s] * w[s] % 97, prod[s]);

    var bad: B.GaloisKey = undefined;
    try testing.expectError(error.InvalidGaloisElement, inst.genGaloisKeyForTest(&kp.sk, 4, rnd, &bad));
    try testing.expectError(error.InvalidGaloisElement, inst.genGaloisKeyForTest(&kp.sk, 33, rnd, &bad));
    try testing.expectEqual(@as(u64, 1), B.galoisElement(0));
    try testing.expectEqual(@as(u64, 1), B.galoisElement(8)); // the order of 3 mod 32 is 8
}

test "modSwitchToNext: drops a limb and still decrypts, fresh and after add" {
    const B = Bfv(params.test_mul);
    const inst = try B.init();
    const Nx = B.Next;
    const next = try Nx.init();
    var prng = std.Random.DefaultPrng.init(0x5e1);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var sk2: Nx.SecretKey = undefined;
    B.modSwitchSecretKey(&kp.sk, &sk2);
    for (0..8) |_| {
        const a = randomPlain(B, rnd);
        const b = randomPlain(B, rnd);
        const ca = inst.encryptForTest(&kp.pk, &a, rnd);
        const cs = inst.add(&ca, &inst.encryptForTest(&kp.pk, &b, rnd));
        const da = next.decrypt(&sk2, &inst.modSwitchToNext(&ca));
        try testing.expectEqualSlices(u64, &a.coeffs, &da.coeffs);
        const ds = next.decrypt(&sk2, &inst.modSwitchToNext(&cs));
        try testing.expectEqualSlices(u64, &B.Plaintext.addRef(&a, &b).coeffs, &ds.coeffs);
    }
    try testing.expectEqual(@as(usize, 1), Nx.num_primes);
}

test "codecs: every object round-trips; foreign parameters, bad residues and lengths are refused" {
    const B = Bfv(test_batch);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0xc0d);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var rlk: B.RelinKey = undefined;
    inst.genRelinKeyForTest(&kp.sk, rnd, &rlk);
    var gk: B.GaloisKey = undefined;
    try inst.genGaloisKeyForTest(&kp.sk, B.galoisElement(1), rnd, &gk);

    var skb: [B.secret_key_bytes]u8 = undefined;
    B.encodeSecretKey(&kp.sk, &skb);
    var sk2: B.SecretKey = undefined;
    try B.decodeSecretKey(&skb, &sk2);
    try testing.expect(sk2.s.eql(&kp.sk.s));

    var pkb: [B.public_key_bytes]u8 = undefined;
    B.encodePublicKey(&kp.pk, &pkb);
    var pk2: B.PublicKey = undefined;
    try B.decodePublicKey(&pkb, &pk2);
    try testing.expect(pk2.p0.eql(&kp.pk.p0) and pk2.p1.eql(&kp.pk.p1));

    var rlb: [B.relin_key_bytes]u8 = undefined;
    B.encodeRelinKey(&rlk, &rlb);
    var rlk2: B.RelinKey = undefined;
    try B.decodeRelinKey(&rlb, &rlk2);
    for (0..B.relin_digits) |i| try testing.expect(rlk2.a[i].eql(&rlk.a[i]) and rlk2.b[i].eql(&rlk.b[i]));

    var gkb: [B.galois_key_bytes]u8 = undefined;
    B.encodeGaloisKey(&gk, &gkb);
    var gk2: B.GaloisKey = undefined;
    try B.decodeGaloisKey(&gkb, &gk2);
    try testing.expectEqual(gk.g, gk2.g);
    for (0..B.relin_digits) |i| try testing.expect(gk2.a[i].eql(&gk.a[i]) and gk2.b[i].eql(&gk.b[i]));

    // A ciphertext travels: encode, decode, evaluate on the decoded copy.
    const pt = randomPlain(B, rnd);
    const ct = inst.encryptForTest(&pk2, &pt, rnd);
    var buf: [B.ciphertextBytes(3)]u8 = undefined;
    const ctb = try B.encodeCiphertext(&ct, &buf);
    try testing.expectEqual(B.ciphertextBytes(2), ctb.len);
    const ct2 = try B.decodeCiphertext(ctb);
    try testing.expectEqualSlices(u64, &pt.coeffs, &inst.decrypt(&sk2, &ct2).coeffs);
    const c3 = inst.mul(&ct2, &ct2);
    const c3b = try B.encodeCiphertext(&c3, &buf);
    const c3d = try B.decodeCiphertext(c3b);
    try testing.expectEqual(@as(usize, 3), c3d.len);
    try testing.expectError(error.NoSpaceLeft, B.encodeCiphertext(&c3, buf[0 .. buf.len - 1]));

    // Refusals.
    try testing.expectError(error.WrongLength, B.decodeSecretKey(skb[0 .. skb.len - 1], &sk2));
    var bad = skb;
    bad[0] = 'X';
    try testing.expectError(error.BadMagic, B.decodeSecretKey(&bad, &sk2));
    bad = skb;
    bad[4] = 2;
    try testing.expectError(error.UnsupportedVersion, B.decodeSecretKey(&bad, &sk2));
    bad = skb;
    bad[5] = @backingInt(B.ObjectKind.public_key);
    try testing.expectError(error.WrongKind, B.decodeSecretKey(&bad, &sk2));
    bad = skb;
    bad[11] ^= 1; // t
    try testing.expectError(error.ParameterMismatch, B.decodeSecretKey(&bad, &sk2));
    bad = skb;
    std.mem.writeInt(u64, bad[B.codec_header_bytes..][0..8], 65537, .little); // = q_0
    try testing.expectError(error.NonCanonical, B.decodeSecretKey(&bad, &sk2));
    var cbad: [B.ciphertextBytes(2)]u8 = undefined;
    _ = try B.encodeCiphertext(&ct, &cbad);
    cbad[B.codec_header_bytes] = 4;
    try testing.expectError(error.BadComponentCount, B.decodeCiphertext(&cbad));
    cbad[B.codec_header_bytes] = 3;
    try testing.expectError(error.WrongLength, B.decodeCiphertext(&cbad));
    var gbad = gkb;
    std.mem.writeInt(u64, gbad[B.codec_header_bytes..][0..8], 2, .little);
    try testing.expectError(error.InvalidGaloisElement, B.decodeGaloisKey(&gbad, &gk2));
    // Another parameter set's header.
    const C = Bfv(params.test_mul);
    var other: [C.secret_key_bytes]u8 = undefined;
    var csk: C.SecretKey = .{ .s = C.Ring.zero(.coeff) };
    C.encodeSecretKey(&csk, &other);
    try testing.expectError(error.ParameterMismatch, B.decodeSecretKey(&other, &sk2));
    _ = &csk;
}

test "secure(4096, 65537, tc128): encrypt, multiply, relinearize, rotate, decrypt" {
    const P = comptime params.secure(4096, 65537, .tc128);
    const B = Bfv(P);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x4096);
    const rnd = prng.random();
    var kp: B.KeyPair = undefined;
    inst.keyGenForTest(rnd, &kp);
    var rlk: B.RelinKey = undefined;
    inst.genRelinKeyForTest(&kp.sk, rnd, &rlk);
    const enc = try BatchEncoder(4096).init(65537);
    var a: [4096]u64 = undefined;
    var b: [4096]u64 = undefined;
    for (&a, &b, 0..) |*x, *y, i| {
        x.* = rnd.uintLessThan(u64, 65537);
        y.* = @intCast(i);
    }
    const ca = inst.encryptForTest(&kp.pk, &(try enc.encodeSlots(&a)), rnd);
    const cb = inst.encryptForTest(&kp.pk, &(try enc.encodeSlots(&b)), rnd);
    const prod = inst.relinearize(&inst.mul(&ca, &cb), &rlk);
    const got = enc.decodeSlots(&inst.decrypt(&kp.sk, &prod));
    for (0..4096) |s| try testing.expectEqual(a[s] * b[s] % 65537, got[s]);
    try testing.expect(inst.noiseBudget(&kp.sk, &prod) > 20);
    var gk: B.GaloisKey = undefined;
    try inst.genGaloisKeyForTest(&kp.sk, B.galoisElement(1), rnd, &gk);
    const rot = enc.decodeSlots(&inst.decrypt(&kp.sk, &inst.applyGalois(&prod, &gk)));
    for (0..2048) |c| try testing.expectEqual(got[(c + 1) % 2048], rot[c]);
}
