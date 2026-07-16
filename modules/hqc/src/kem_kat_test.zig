// SPDX-License-Identifier: MIT
//! kem_kat_test — Part 3's definitive deliverable: byte-exact NIST KAT
//! reproduction for HQC-128/192/256, driven exactly the way the
//! reference's own `main_kat.c` harness drives it (see
//! kat_vectors_kem.zig's module doc): seed a single continuing
//! `prng.Prng` from the `.rsp` vector's 48-byte `seed`, draw `seed_kem`
//! (32 B) for `keypair`, then continue drawing `coins` (m || salt) off
//! the SAME Prng for `encaps` — the exact `prng_get_bytes` call sequence
//! `crypto_kem_keypair` then `crypto_kem_enc` make on one shared DRBG
//! stream in the reference.
//!
//! Also: a random-coins round-trip property test (keypair/encaps/decaps
//! agree on the shared secret across several random seeds, all three
//! parameter sets) and a decaps-failure/implicit-reject test (a
//! corrupted ciphertext makes `decaps` return the `J(...)`-derived
//! rejection value — deterministically, not a crash, and not equal to
//! the real shared secret).

const std = @import("std");
const testing = std.testing;

const params = @import("params.zig");
const prng = @import("prng.zig");
const reedsolomon = @import("reedsolomon.zig");
const kem = @import("kem.zig");
const v = @import("kat_vectors_kem.zig");

const Kem128 = kem.Kem(params.hqc128, reedsolomon.generator_hqc128);
const Kem192 = kem.Kem(params.hqc192, reedsolomon.generator_hqc192);
const Kem256 = kem.Kem(params.hqc256, reedsolomon.generator_hqc256);

fn hexBytes(comptime len: usize, hex: []const u8) [len]u8 {
    var out: [len]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&out, hex) catch unreachable;
    std.debug.assert(decoded.len == len);
    return out;
}

// ── byte-exact NIST KAT (the definitive check) ──────────────────────────

fn checkKat(comptime Kem: type, vec: v.Vector) !void {
    const seed = hexBytes(48, vec.seed);

    // One continuing Prng stream across keypair + encaps, exactly as
    // main_kat.c's single `prng_init(seed, ...)` feeds both
    // `crypto_kem_keypair` and `crypto_kem_enc` in sequence.
    var rsp_prng = prng.Prng.init(&seed, &[_]u8{});

    var seed_kem: [params.seed_bytes]u8 = undefined;
    rsp_prng.getBytes(&seed_kem);
    const kp = Kem.keypair(&seed_kem);

    const want_pk = hexBytes(Kem.ek_bytes, vec.pk);
    try testing.expectEqualSlices(u8, &want_pk, &kp.ek);
    const want_sk = hexBytes(Kem.dk_bytes, vec.sk);
    try testing.expectEqualSlices(u8, &want_sk, &kp.dk);

    var coins: [Kem.coins_bytes]u8 = undefined;
    rsp_prng.getBytes(&coins);
    const enc = Kem.encaps(kp.ek, &coins);

    const want_ct = hexBytes(Kem.ct_bytes, vec.ct);
    try testing.expectEqualSlices(u8, &want_ct, &enc.ct);
    const want_ss = hexBytes(Kem.ss_bytes, vec.ss);
    try testing.expectEqualSlices(u8, &want_ss, &enc.ss);

    // decaps on the genuine ciphertext must recover the same ss (the
    // .rsp itself doesn't publish this as a separate field -- it's what
    // main_kat.c's own internal `memcmp(ss, ss1, ...)` self-check
    // verifies -- so this is us reproducing that self-check).
    const dec_ss = Kem.decaps(kp.dk, enc.ct);
    try testing.expectEqualSlices(u8, &want_ss, &dec_ss);
}

test "NIST KAT: HQC-128 count 0..2 byte-exact pk/sk/ct/ss, decaps agrees" {
    for (v.hqc128) |vec| try checkKat(Kem128, vec);
}

test "NIST KAT: HQC-192 count 0..2 byte-exact pk/sk/ct/ss, decaps agrees" {
    for (v.hqc192) |vec| try checkKat(Kem192, vec);
}

test "NIST KAT: HQC-256 count 0..2 byte-exact pk/sk/ct/ss, decaps agrees" {
    for (v.hqc256) |vec| try checkKat(Kem256, vec);
}

// ── round-trip property test: random coins, three parameter sets ───────

fn testRoundTrip(comptime Kem: type, seed_val: u64) !void {
    var rng = std.Random.DefaultPrng.init(seed_val);
    const random = rng.random();

    var seed_kem: [params.seed_bytes]u8 = undefined;
    random.bytes(&seed_kem);
    const kp = Kem.keypair(&seed_kem);

    var coins: [Kem.coins_bytes]u8 = undefined;
    random.bytes(&coins);
    const enc = Kem.encaps(kp.ek, &coins);

    const dec_ss = Kem.decaps(kp.dk, enc.ct);
    try testing.expectEqualSlices(u8, &enc.ss, &dec_ss);
}

test "round-trip: HQC-128 keypair/encaps/decaps agree across random coins" {
    for (0..4) |i| try testRoundTrip(Kem128, i);
}

test "round-trip: HQC-192 keypair/encaps/decaps agree across random coins" {
    for (10..13) |i| try testRoundTrip(Kem192, i);
}

test "round-trip: HQC-256 keypair/encaps/decaps agree across random coins" {
    for (20..23) |i| try testRoundTrip(Kem256, i);
}

// ── decaps-failure / implicit-rejection ─────────────────────────────────

fn testImplicitReject(comptime Kem: type, seed_val: u64) !void {
    var rng = std.Random.DefaultPrng.init(seed_val);
    const random = rng.random();

    var seed_kem: [params.seed_bytes]u8 = undefined;
    random.bytes(&seed_kem);
    const kp = Kem.keypair(&seed_kem);

    var coins: [Kem.coins_bytes]u8 = undefined;
    random.bytes(&coins);
    const enc = Kem.encaps(kp.ek, &coins);

    // Flip one bit inside u (the ciphertext's leading component) --
    // decaps must not crash, and must NOT recover the real ss.
    var corrupted = enc.ct;
    corrupted[0] ^= 0x01;

    const rejected_ss = Kem.decaps(kp.dk, corrupted);
    try testing.expect(!std.mem.eql(u8, &rejected_ss, &enc.ss));

    // The implicit-reject value is J(H(ek), sigma, ct) -- a deterministic
    // hash, not randomness -- so decapsing the same corrupted ct twice
    // must yield the identical rejection value both times.
    const rejected_ss2 = Kem.decaps(kp.dk, corrupted);
    try testing.expectEqualSlices(u8, &rejected_ss, &rejected_ss2);

    // Also corrupt the salt (the ciphertext's tail) -- same contract.
    var corrupted_salt = enc.ct;
    corrupted_salt[corrupted_salt.len - 1] ^= 0x80;
    const rejected_salt_ss = Kem.decaps(kp.dk, corrupted_salt);
    try testing.expect(!std.mem.eql(u8, &rejected_salt_ss, &enc.ss));
}

test "implicit reject: corrupted ciphertext decaps returns a differing, deterministic ss" {
    try testImplicitReject(Kem128, 100);
    try testImplicitReject(Kem192, 101);
    try testImplicitReject(Kem256, 102);
}
